use serde_json::Map;

use serde_json::Value;

use crate::base64url;

use crate::json::JsonErrors;

use crate::json::parse_object;

use crate::jwa::JwaSigningAlgorithm;

use super::constants::MAX_TOKEN_LEN;

use super::constants::MAX_HEADER_LEN;

use super::constants::SUPPORTED_CRIT_PARAMS;

use super::constants::JWS_REGISTERED_HEADER_PARAMS;

use super::header::PayloadEncoding;

use super::errors::JwsParseErrors;

/// A compact JWS that passed the checks that need no key, and nothing more: the signature has
/// NOT been verified, so nothing in it is authenticated.
///
/// It can only be built through [`parse`](Self::parse).
pub struct UnverifiedJws<'a> {
    header: UnverifiedHeader,

    payload: UnverifiedPayload<'a>,

    /// The signature as received, base64url. Its length already fits `alg`; it is decoded
    /// when it is verified.
    signature: &'a str,

    /// The token up to the last `.`: `header.payload`, or `header.` when the payload is
    /// detached. For an attached payload it is the exact signing input (RFC 7515 §5.1), so
    /// nothing is rebuilt or re-encoded.
    signing_prefix: &'a str,
}

/// The protected header as it came, parsed but not authenticated.
pub struct UnverifiedHeader {
    alg: JwaSigningAlgorithm,

    cty: Option<String>,

    kid: Option<String>,

    typ: Option<String>,

    /// Every other member, as received. Nothing in here is fetched or trusted (`jku`, `x5u`).
    extra: Map<String, Value>,

    encoding: PayloadEncoding,
}

pub enum UnverifiedPayload<'a> {
    /// The segment is empty: the payload travels outside the token (RFC 7515 Appendix F,
    /// RFC 7797 §5.2).
    Detached,

    /// The payload as received, base64url.
    Attached(&'a str),
}

impl<'a> UnverifiedJws<'a> {
    /// Splits and checks a compact JWS: sizes, header shape, `alg`, `crit`, `b64` and the
    /// length of the signature. No cryptography is done.
    pub fn parse(token: &'a str) -> Result<Self, JwsParseErrors> {
        Self::parse_with(token, &SUPPORTED_CRIT_PARAMS)
    }

    // The set of supported `crit` extensions is a parameter so that it can become something
    // the caller opts into, without touching the parser. Today it is always the closed one.
    fn parse_with(token: &'a str, supported_crit: &[&str]) -> Result<Self, JwsParseErrors> {
        if token.len() > MAX_TOKEN_LEN {
            return Err(JwsParseErrors::TokenTooLarge);
        }

        let mut segments = token.split('.');

        let (Some(header_b64), Some(payload_b64), Some(signature), None) = (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ) else {
            return Err(JwsParseErrors::NotCompactSerialization);
        };

        let header = UnverifiedHeader::parse(header_b64, supported_crit)?;

        let payload = if payload_b64.is_empty() {
            UnverifiedPayload::Detached
        } else if header.encoding == PayloadEncoding::Unencoded {
            return Err(JwsParseErrors::UnencodedAttachedPayload);
        } else {
            base64url::decoded_len(payload_b64.len())
                .map_err(|_| JwsParseErrors::PayloadNotBase64Url)?;

            UnverifiedPayload::Attached(payload_b64)
        };

        // The cheap filter: refuse a signature that can't be the one `alg` produces before
        // spending anything on it. RS* and PS* have no fixed length, only a non-empty one.
        let signature_len =
            base64url::decoded_len(signature.len()).map_err(|_| JwsParseErrors::SignatureLength)?;

        if signature_len == 0
            || header
                .alg
                .signature_len()
                .is_some_and(|expected| expected != signature_len)
        {
            return Err(JwsParseErrors::SignatureLength);
        }

        // `header.payload`, or `header.` when detached: the same slice either way.
        let signing_prefix = &token[..header_b64.len() + 1 + payload_b64.len()];

        Ok(Self {
            header,
            payload,
            signature,
            signing_prefix,
        })
    }

    pub fn header(&self) -> &UnverifiedHeader {
        &self.header
    }

    pub fn payload(&self) -> &UnverifiedPayload<'a> {
        &self.payload
    }

    /// The signature as received, base64url.
    pub fn signature(&self) -> &'a str {
        self.signature
    }

    pub(super) fn signing_prefix(&self) -> &'a str {
        self.signing_prefix
    }
}

impl<'a> UnverifiedPayload<'a> {
    /// The payload as received, base64url. `None` when it is detached.
    pub fn encoded(&self) -> Option<&'a str> {
        match self {
            Self::Attached(encoded) => Some(encoded),

            Self::Detached => None,
        }
    }

    /// Decodes the payload. NOTHING here is authenticated: use it only to decide whether it is
    /// worth checking the signature, never to act on it. `None` when it is detached.
    pub fn decode_unverified(&self) -> Option<Result<Vec<u8>, base64url::Base64DecodingErrors>> {
        self.encoded().map(base64url::decode)
    }
}

impl UnverifiedHeader {
    fn parse(header_b64: &str, supported_crit: &[&str]) -> Result<Self, JwsParseErrors> {
        // The cap is on the encoded form, so an oversized header is refused before decoding it.
        if header_b64.len() > base64url::encoded_len(MAX_HEADER_LEN) {
            return Err(JwsParseErrors::HeaderTooLarge);
        }

        let json = base64url::decode(header_b64).map_err(|_| JwsParseErrors::HeaderNotBase64Url)?;

        let mut members = parse_object(&json, MAX_HEADER_LEN).map_err(|error| match error {
            JsonErrors::TooLarge => JwsParseErrors::HeaderTooLarge,

            JsonErrors::Malformed => JwsParseErrors::HeaderNotJson,

            JsonErrors::NotAnObject => JwsParseErrors::HeaderNotAnObject,

            JsonErrors::DuplicateMembers(names) => JwsParseErrors::DuplicateHeaderParams(names),
        })?;

        let alg = match members.remove("alg") {
            None => return Err(JwsParseErrors::MissingAlg),

            Some(value @ Value::String(_)) => serde_json::from_value::<JwaSigningAlgorithm>(value)
                .map_err(|_| JwsParseErrors::UnsupportedAlg)?,

            Some(_) => return Err(JwsParseErrors::HeaderParamWrongType("alg")),
        };

        let crit = match members.remove("crit") {
            Some(value) => Some(Self::read_crit(value, supported_crit)?),

            None => None,
        };

        // RFC 7515 §4.1.11: every name `crit` lists has to be a member of the header.
        if let Some(names) = &crit {
            if let Some(missing) = names.iter().find(|name| !members.contains_key(*name)) {
                return Err(JwsParseErrors::CritMissingParam(missing.clone()));
            }
        }

        let b64_in_crit = crit
            .as_ref()
            .is_some_and(|names| names.iter().any(|name| name == "b64"));

        // RFC 7797 §3: `true` is the default, so it changes nothing and is not kept.
        let encoding = match members.remove("b64") {
            None | Some(Value::Bool(true)) => PayloadEncoding::Base64Url,

            Some(Value::Bool(false)) if b64_in_crit => PayloadEncoding::Unencoded,

            Some(Value::Bool(false)) => return Err(JwsParseErrors::B64WithoutCrit),

            Some(_) => return Err(JwsParseErrors::HeaderParamWrongType("b64")),
        };

        Ok(Self {
            alg,
            cty: Self::take_string(&mut members, "cty")?,
            typ: Self::take_string(&mut members, "typ")?,
            kid: Self::take_string(&mut members, "kid")?,
            extra: members,
            encoding,
        })
    }

    pub fn alg(&self) -> JwaSigningAlgorithm {
        self.alg
    }

    pub fn typ(&self) -> Option<&str> {
        self.typ.as_deref()
    }

    pub fn cty(&self) -> Option<&str> {
        self.cty.as_deref()
    }

    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// Every member other than `alg`, `typ`, `cty`, `kid`, `crit` and `b64`.
    pub fn extra(&self) -> &Map<String, Value> {
        &self.extra
    }

    pub(super) fn encoding(&self) -> PayloadEncoding {
        self.encoding
    }

    /// Reads `crit` (RFC 7515 §4.1.11): a non-empty list of names, none registered by JWS and all
    /// of them extensions the library implements.
    fn read_crit(value: Value, supported: &[&str]) -> Result<Vec<String>, JwsParseErrors> {
        let Value::Array(items) = value else {
            return Err(JwsParseErrors::HeaderParamWrongType("crit"));
        };

        if items.is_empty() {
            return Err(JwsParseErrors::EmptyCrit);
        }

        let mut names = Vec::with_capacity(items.len());

        for item in items {
            let Value::String(name) = item else {
                return Err(JwsParseErrors::HeaderParamWrongType("crit"));
            };

            if JWS_REGISTERED_HEADER_PARAMS.contains(&name.as_str()) {
                return Err(JwsParseErrors::CritRegisteredParam(name));
            }

            if !supported.contains(&name.as_str()) {
                return Err(JwsParseErrors::CritUnsupported(name));
            }

            names.push(name);
        }

        Ok(names)
    }

    fn take_string(
        members: &mut Map<String, Value>,
        name: &'static str,
    ) -> Result<Option<String>, JwsParseErrors> {
        match members.remove(name) {
            None => Ok(None),

            Some(Value::String(value)) => Ok(Some(value)),

            Some(_) => Err(JwsParseErrors::HeaderParamWrongType(name)),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    // RFC 7515 Appendix A.1.
    const A1: &str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.\
        eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.\
        dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    // RFC 7797 §4.2: unencoded, detached.
    const RFC7797: &str = "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..\
        A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY";

    // A signature of the right length for HS256 (32 bytes).
    const SIG32: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    /// Parses a token whose header is `header` (JSON text) and whose payload is attached.
    fn error(header: &str) -> JwsParseErrors {
        let token = format!("{}.cGF5.{SIG32}", base64url::encode(header.as_bytes()));

        UnverifiedJws::parse(&token)
            .err()
            .expect("should be refused")
    }

    /// Same, for the headers that are expected to be accepted: `check` sees the parsed token.
    fn accepted(header: &str, check: impl FnOnce(&UnverifiedJws)) {
        let token = format!("{}.cGF5.{SIG32}", base64url::encode(header.as_bytes()));

        check(&UnverifiedJws::parse(&token).expect("should be accepted"));
    }

    #[test]
    fn rfc7515_appendix_a1() {
        let jws = UnverifiedJws::parse(A1).unwrap();

        assert_eq!(jws.header().alg(), JwaSigningAlgorithm::Hs256);
        assert_eq!(jws.header().typ(), Some("JWT"));
        assert_eq!(jws.header().encoding(), PayloadEncoding::Base64Url);
        assert_eq!(jws.signature(), SIG32);

        let payload = jws.payload().decode_unverified().unwrap().unwrap();

        assert!(payload.starts_with(b"{\"iss\":\"joe\""));

        // The signing input is the token up to the last dot, byte for byte.
        assert_eq!(jws.signing_prefix(), A1.rsplit_once('.').unwrap().0);
    }

    #[test]
    fn rfc7797_section_4_2_is_unencoded_and_detached() {
        let jws = UnverifiedJws::parse(RFC7797).unwrap();

        assert_eq!(jws.header().alg(), JwaSigningAlgorithm::Hs256);
        assert_eq!(jws.header().encoding(), PayloadEncoding::Unencoded);
        assert!(matches!(jws.payload(), UnverifiedPayload::Detached));
        assert!(jws.payload().decode_unverified().is_none());

        // `header.`: what signs is that plus the payload the caller brings.
        assert!(jws.signing_prefix().ends_with('.'));
        assert_eq!(jws.signing_prefix().matches('.').count(), 1);

        // `b64` and `crit` are consumed, not left in `extra`.
        assert!(jws.header().extra().is_empty());
    }

    #[test]
    fn unencoded_payload_with_a_dot_inside_the_token_is_refused() {
        // The header and signature of RFC 7797 §4.2 with the payload `$.02` put inside the
        // token. The dot makes it four segments, so it is not a compact JWS (§5.2).
        let attached = "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19.$.02.\
            A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY";

        assert_eq!(
            UnverifiedJws::parse(attached).err(),
            Some(JwsParseErrors::NotCompactSerialization)
        );
    }

    #[test]
    fn unknown_members_are_kept_in_extra() {
        accepted(
            r#"{"alg":"HS256","kid":"k","foo":1,"jku":"https://e.example"}"#,
            |jws| {
                assert_eq!(jws.header().kid(), Some("k"));
                assert_eq!(jws.header().extra()["foo"], json!(1));
                assert_eq!(jws.header().extra()["jku"], json!("https://e.example"));
            },
        );
    }

    #[test]
    fn b64_true_is_ignored_with_or_without_crit() {
        for header in [
            r#"{"alg":"HS256","b64":true}"#,
            r#"{"alg":"HS256","b64":true,"crit":["b64"]}"#,
        ] {
            accepted(header, |jws| {
                assert_eq!(jws.header().encoding(), PayloadEncoding::Base64Url);
                assert!(jws.header().extra().is_empty());
            });
        }
    }

    #[test]
    fn token_shape() {
        for input in ["", "a", "a.b", "a.b.c.d", "...", "a.b.c.d.e"] {
            assert_eq!(
                UnverifiedJws::parse(input).err(),
                Some(JwsParseErrors::NotCompactSerialization),
                "{input:?}"
            );
        }

        // Three empty segments do have the shape; they fail on the empty header instead.
        assert_eq!(
            UnverifiedJws::parse("..").err(),
            Some(JwsParseErrors::HeaderNotJson)
        );
    }

    #[test]
    fn size_caps() {
        let huge = "a".repeat(MAX_TOKEN_LEN + 1);

        assert_eq!(
            UnverifiedJws::parse(&huge).err(),
            Some(JwsParseErrors::TokenTooLarge)
        );

        let big_header = "a".repeat(base64url::encoded_len(MAX_HEADER_LEN) + 1);

        assert_eq!(
            UnverifiedJws::parse(&format!("{big_header}.cGF5.{SIG32}")).err(),
            Some(JwsParseErrors::HeaderTooLarge)
        );
    }

    #[test]
    fn header_is_not_base64url_or_not_json_or_not_an_object() {
        use JwsParseErrors::*;

        assert_eq!(
            UnverifiedJws::parse(&format!("a+b=.cGF5.{SIG32}")).err(),
            Some(HeaderNotBase64Url)
        );

        assert_eq!(error("not json"), HeaderNotJson);
        assert_eq!(error(""), HeaderNotJson);
        assert_eq!(error(r#"["alg","HS256"]"#), HeaderNotAnObject);
        assert_eq!(error("null"), HeaderNotAnObject);
    }

    #[test]
    fn duplicate_header_params() {
        assert_eq!(
            error(r#"{"alg":"HS256","alg":"HS512","kid":"a","kid":"b"}"#),
            JwsParseErrors::DuplicateHeaderParams(vec!["alg".into(), "kid".into()])
        );
    }

    #[test]
    fn alg_is_required_and_closed() {
        use JwsParseErrors::*;

        assert_eq!(error("{}"), MissingAlg);
        assert_eq!(error(r#"{"alg":1}"#), HeaderParamWrongType("alg"));
        assert_eq!(error(r#"{"alg":null}"#), HeaderParamWrongType("alg"));

        for alg in [
            "none", "None", "EdDSA", "RS1", "hs256", "RSA1_5", "ES256K", "",
        ] {
            assert_eq!(
                error(&format!(r#"{{"alg":"{alg}"}}"#)),
                UnsupportedAlg,
                "{alg}"
            );
        }
    }

    #[test]
    fn typ_cty_kid_must_be_strings() {
        for name in ["typ", "cty", "kid"] {
            assert_eq!(
                error(&format!(r#"{{"alg":"HS256","{name}":1}}"#)),
                JwsParseErrors::HeaderParamWrongType(name)
            );
        }
    }

    #[test]
    fn crit_rules() {
        use JwsParseErrors::*;

        assert_eq!(error(r#"{"alg":"HS256","crit":[]}"#), EmptyCrit);

        assert_eq!(
            error(r#"{"alg":"HS256","crit":"b64"}"#),
            HeaderParamWrongType("crit")
        );
        assert_eq!(
            error(r#"{"alg":"HS256","crit":[1]}"#),
            HeaderParamWrongType("crit")
        );

        // `sub` is a JWT claim, not an extension the library implements, member or not.
        assert_eq!(
            error(r#"{"alg":"HS256","crit":["sub"]}"#),
            CritUnsupported("sub".into())
        );
        assert_eq!(
            error(r#"{"alg":"HS256","sub":"x","crit":["sub"]}"#),
            CritUnsupported("sub".into())
        );
        assert_eq!(
            error(r#"{"alg":"HS256","my_param":"x","crit":["my_param"]}"#),
            CritUnsupported("my_param".into())
        );

        // Names JWS defines can't be listed (RFC 7515 §4.1.11), whether or not they are there.
        for name in ["alg", "kid", "typ", "crit"] {
            assert_eq!(
                error(&format!(
                    r#"{{"alg":"HS256","kid":"k","typ":"t","crit":["{name}"]}}"#
                )),
                CritRegisteredParam(name.into()),
                "{name}"
            );
        }

        // A supported extension that the header doesn't carry.
        assert_eq!(
            error(r#"{"alg":"HS256","crit":["b64"]}"#),
            CritMissingParam("b64".into())
        );
    }

    #[test]
    fn b64_rules() {
        use JwsParseErrors::*;

        assert_eq!(error(r#"{"alg":"HS256","b64":false}"#), B64WithoutCrit);
        assert_eq!(
            error(r#"{"alg":"HS256","b64":"false"}"#),
            HeaderParamWrongType("b64")
        );
        assert_eq!(
            error(r#"{"alg":"HS256","b64":0}"#),
            HeaderParamWrongType("b64")
        );
        assert_eq!(
            error(r#"{"alg":"HS256","b64":null}"#),
            HeaderParamWrongType("b64")
        );
    }

    #[test]
    fn unencoded_payload_inside_the_token_is_refused() {
        let header = base64url::encode(br#"{"alg":"HS256","b64":false,"crit":["b64"]}"#);

        assert_eq!(
            UnverifiedJws::parse(&format!("{header}.cGF5.{SIG32}")).err(),
            Some(JwsParseErrors::UnencodedAttachedPayload)
        );
    }

    #[test]
    fn detached_payload_with_base64url_encoding_is_accepted() {
        let header = base64url::encode(br#"{"alg":"HS256"}"#);

        let token = format!("{header}..{SIG32}");

        let jws = UnverifiedJws::parse(&token).unwrap();

        assert!(matches!(jws.payload(), UnverifiedPayload::Detached));
    }

    #[test]
    fn payload_with_an_impossible_length() {
        // A length of 1 (mod 4) can't come out of any encoder.
        let header = base64url::encode(br#"{"alg":"HS256"}"#);

        assert_eq!(
            UnverifiedJws::parse(&format!("{header}.a.{SIG32}")).err(),
            Some(JwsParseErrors::PayloadNotBase64Url)
        );
    }

    #[test]
    fn signature_length_is_checked_against_alg() {
        let header = base64url::encode(br#"{"alg":"HS256"}"#);

        let longer = format!("{SIG32}AA");

        for signature in ["", "a", &SIG32[..SIG32.len() - 1], &longer] {
            assert_eq!(
                UnverifiedJws::parse(&format!("{header}.cGF5.{signature}")).err(),
                Some(JwsParseErrors::SignatureLength),
                "{signature:?}"
            );
        }

        // HS512 wants 64 bytes: the 32-byte signature of HS256 is refused.
        let header = base64url::encode(br#"{"alg":"HS512"}"#);

        assert_eq!(
            UnverifiedJws::parse(&format!("{header}.cGF5.{SIG32}")).err(),
            Some(JwsParseErrors::SignatureLength)
        );
    }

    #[test]
    fn rsa_signature_only_has_to_be_non_empty() {
        let header = base64url::encode(br#"{"alg":"RS256"}"#);

        assert!(UnverifiedJws::parse(&format!("{header}.cGF5.{SIG32}")).is_ok());

        assert_eq!(
            UnverifiedJws::parse(&format!("{header}.cGF5.")).err(),
            Some(JwsParseErrors::SignatureLength)
        );
    }

    #[test]
    fn crit_set_is_closed_by_default_but_the_parameter_works() {
        let header = base64url::encode(br#"{"alg":"HS256","x":1,"crit":["x"]}"#);

        let token = format!("{header}.cGF5.{SIG32}");

        assert_eq!(
            UnverifiedJws::parse(&token).err(),
            Some(JwsParseErrors::CritUnsupported("x".into()))
        );

        assert!(UnverifiedJws::parse_with(&token, &["x"]).is_ok());
    }
}
