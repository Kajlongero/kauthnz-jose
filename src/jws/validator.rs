use std::sync::OnceLock;

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

use super::header::TokenType;

use super::header::ContentType;

use super::header::PayloadEncoding;

use super::errors::JwsParseErrors;

/// A compact JWS, in the stage of being validated: the rules are checked here, before any
/// cryptography, and then its signature is verified.
///
/// In this crate *validating* is checking the rules (the shape of the token, `alg`, `crit`,
/// `b64`, and what is expected of `typ` and `cty`), and *verifying* is checking the integrity,
/// that is, the signature. Everything the validator hands out before `verify` is `Unverified`;
/// what comes out of `verify` is `Verified`. (RFC 7515 and RFC 7519 use the two words more
/// loosely; this is the meaning they have here.)
///
/// `new` only splits the token, so it is cheap and it never looks inside the header. Each part
/// is decoded, and checked, the first time it is asked for, and kept: asking again costs
/// nothing, and `verify` takes what was read instead of reading it again. That is what makes it
/// possible to look at the header (to pick a key by `kid`, say), apply rules of your own, and
/// only then verify, without any of the work being done twice.
pub struct JwsValidator<'a> {
    header_b64: &'a str,

    payload_b64: &'a str,

    signature_b64: &'a str,

    /// The token up to the last `.`: `header.payload`, or `header.` when the payload is
    /// detached. For an attached payload it is the exact signing input (RFC 7515 §5.1), so
    /// nothing is rebuilt or re-encoded.
    signing_prefix: &'a str,

    header: OnceLock<Result<UnverifiedHeader, JwsParseErrors>>,

    payload: OnceLock<Result<UnverifiedPayload, JwsParseErrors>>,

    signature: OnceLock<Result<Vec<u8>, JwsParseErrors>>,

    /// The `typ` the token has to carry, when one is demanded.
    pub(super) expected_typ: Option<&'static str>,

    /// The `cty` the token has to carry, when one is demanded.
    pub(super) expected_cty: Option<&'static str>,
}

/// The protected header as it came, parsed but not authenticated.
pub struct UnverifiedHeader {
    alg: JwaSigningAlgorithm,

    typ: Option<String>,

    cty: Option<String>,

    kid: Option<String>,

    /// Every other member, as received. Nothing in here is fetched or trusted (`jku`, `x5u`).
    extra: Map<String, Value>,

    encoding: PayloadEncoding,
}

/// The payload of an unverified JWS, decoded. NOTHING here is authenticated: use it only to
/// decide whether it is worth checking the signature, never to act on it.
pub enum UnverifiedPayload {
    /// The segment is empty: the payload travels outside the token (RFC 7515 Appendix F,
    /// RFC 7797 §5.2).
    Detached,

    Attached(Vec<u8>),
}

impl<'a> JwsValidator<'a> {
    /// Splits a compact JWS in its three segments (RFC 7515 §7.1), after checking the size of
    /// the whole token.
    pub fn new(token: &'a str) -> Result<Self, JwsParseErrors> {
        if token.len() > MAX_TOKEN_LEN {
            return Err(JwsParseErrors::TokenTooLarge);
        }

        // Cut at the last dot, then at the first one: nothing is indexed by position, so there
        // is no cut that can be wrong. `header.payload` (or `header.` when the payload is
        // detached) is the signing input as it came, and what is left of it is checked below.
        let Some((signing_prefix, signature)) = token.rsplit_once('.') else {
            return Err(JwsParseErrors::NotCompactSerialization);
        };

        let Some((header, payload)) = signing_prefix.split_once('.') else {
            return Err(JwsParseErrors::NotCompactSerialization);
        };

        // The header ends at the first dot and the signature starts after the last, so any
        // other dot is in the middle: more than three segments.
        if payload.contains('.') {
            return Err(JwsParseErrors::NotCompactSerialization);
        }

        Ok(Self {
            header_b64: header,
            payload_b64: payload,
            signature_b64: signature,
            signing_prefix,
            expected_typ: None,
            expected_cty: None,
            header: OnceLock::new(),
            payload: OnceLock::new(),
            signature: OnceLock::new(),
        })
    }

    /// Requires the `typ` of the token to be `T::TYP` (RFC 7515 §4.1.9). A token without one is
    /// refused. Without this, `typ` is not checked at all. It is a cheap early refusal, made
    /// before any cryptography; the same check can be made again on the verified token.
    pub fn typ<T: TokenType>(mut self) -> Self {
        self.expected_typ = Some(T::TYP);

        self
    }

    /// Requires the `cty` of the token to be `C::CTY` (RFC 7515 §4.1.10). A token without one is
    /// refused. Without this, `cty` is not checked at all.
    pub fn cty<C: ContentType>(mut self) -> Self {
        self.expected_cty = Some(C::CTY);

        self
    }

    /// The header segment as it came, base64url.
    pub fn header_b64(&self) -> &'a str {
        self.header_b64
    }

    /// The payload segment as it came, base64url. Empty when the payload is detached.
    pub fn payload_b64(&self) -> &'a str {
        self.payload_b64
    }

    /// The signature segment as it came, base64url.
    pub fn signature_b64(&self) -> &'a str {
        self.signature_b64
    }

    /// Decodes and checks the protected header: size, `alg`, `crit` and `b64`. It is done the
    /// first time; after that it is the same header.
    pub fn decode_header(&self) -> Result<&UnverifiedHeader, JwsParseErrors> {
        self.header
            .get_or_init(|| UnverifiedHeader::decode(self.header_b64, &SUPPORTED_CRIT_PARAMS))
            .as_ref()
            .map_err(Clone::clone)
    }

    /// Decodes the payload. It needs the header, for `b64`, so it reads it too.
    pub fn decode_payload(&self) -> Result<&UnverifiedPayload, JwsParseErrors> {
        self.payload
            .get_or_init(|| {
                let encoding = self.decode_header()?.encoding();

                UnverifiedPayload::decode(self.payload_b64, encoding)
            })
            .as_ref()
            .map_err(Clone::clone)
    }

    /// Decodes the signature after the cheap filter: one that can't be the one `alg` produces
    /// is refused before spending anything on it. RS* and PS* have no fixed length, only a
    /// non-empty one. The `alg` is the one of the header.
    pub fn decode_signature(&self) -> Result<&[u8], JwsParseErrors> {
        self.signature
            .get_or_init(|| {
                let alg = self.decode_header()?.alg();

                let len = base64url::decoded_len(self.signature_b64.len())
                    .map_err(|_| JwsParseErrors::SignatureLength)?;

                if len == 0 || alg.signature_len().is_some_and(|expected| expected != len) {
                    return Err(JwsParseErrors::SignatureLength);
                }

                base64url::decode(self.signature_b64)
                    .map_err(|_| JwsParseErrors::SignatureNotBase64Url)
            })
            .as_ref()
            .map(Vec::as_slice)
            .map_err(Clone::clone)
    }

    pub(super) fn signing_prefix(&self) -> &'a str {
        self.signing_prefix
    }

    /// Hands over the header and the payload, what the verified types are made of. What was
    /// already decoded is moved, not decoded again; what wasn't is decoded now.
    pub(super) fn into_decoded(
        self,
    ) -> Result<(UnverifiedHeader, UnverifiedPayload), JwsParseErrors> {
        let header = match self.header.into_inner() {
            Some(header) => header?,

            None => UnverifiedHeader::decode(self.header_b64, &SUPPORTED_CRIT_PARAMS)?,
        };

        let payload = match self.payload.into_inner() {
            Some(payload) => payload?,

            None => UnverifiedPayload::decode(self.payload_b64, header.encoding())?,
        };

        Ok((header, payload))
    }
}

impl UnverifiedPayload {
    fn decode(payload_b64: &str, encoding: PayloadEncoding) -> Result<Self, JwsParseErrors> {
        if payload_b64.is_empty() {
            return Ok(Self::Detached);
        }

        if encoding == PayloadEncoding::Unencoded {
            return Err(JwsParseErrors::UnencodedAttachedPayload);
        }

        base64url::decode(payload_b64)
            .map(Self::Attached)
            .map_err(|_| JwsParseErrors::PayloadNotBase64Url)
    }

    /// The decoded payload. `None` when it is detached.
    pub fn attached(&self) -> Option<&[u8]> {
        match self {
            Self::Attached(bytes) => Some(bytes),

            Self::Detached => None,
        }
    }

    pub fn is_detached(&self) -> bool {
        matches!(self, Self::Detached)
    }

    /// Hands the decoded payload over, for the verified one that takes its place.
    pub(super) fn into_attached(self) -> Option<Vec<u8>> {
        match self {
            Self::Attached(bytes) => Some(bytes),

            Self::Detached => None,
        }
    }
}

impl UnverifiedHeader {
    fn decode(header_b64: &str, supported_crit: &[&str]) -> Result<Self, JwsParseErrors> {
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
            encoding,
            typ: Self::take_string(&mut members, "typ")?,
            cty: Self::take_string(&mut members, "cty")?,
            kid: Self::take_string(&mut members, "kid")?,
            extra: members,
        })
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

    /// Everything the reader gives, asked for in the order a verifier asks for it: header,
    /// payload and signature. The first error is the one that comes out.
    fn read(token: &str) -> Result<JwsValidator<'_>, JwsParseErrors> {
        let jws = JwsValidator::new(token)?;

        jws.decode_header()?;
        jws.decode_payload()?;
        jws.decode_signature()?;

        Ok(jws)
    }

    /// Reads a token whose header is `header` (JSON text) and whose payload is attached.
    fn error(header: &str) -> JwsParseErrors {
        let token = format!("{}.cGF5.{SIG32}", base64url::encode(header.as_bytes()));

        read(&token).err().expect("should be refused")
    }

    /// Same, for the headers that are expected to be accepted: `check` sees what was read.
    fn accepted(header: &str, check: impl FnOnce(&JwsValidator)) {
        let token = format!("{}.cGF5.{SIG32}", base64url::encode(header.as_bytes()));

        check(&read(&token).expect("should be accepted"));
    }

    #[test]
    fn rfc7515_appendix_a1() {
        let jws = read(A1).unwrap();

        let header = jws.decode_header().unwrap();

        assert_eq!(header.alg(), JwaSigningAlgorithm::Hs256);
        assert_eq!(header.typ(), Some("JWT"));
        assert_eq!(header.encoding(), PayloadEncoding::Base64Url);

        assert_eq!(base64url::encode(jws.decode_signature().unwrap()), SIG32);

        assert!(
            jws.decode_payload()
                .unwrap()
                .attached()
                .unwrap()
                .starts_with(b"{\"iss\":\"joe\"")
        );

        // The signing input is the token up to the last dot, byte for byte.
        assert_eq!(jws.signing_prefix(), A1.rsplit_once('.').unwrap().0);
    }

    #[test]
    fn rfc7797_section_4_2_is_unencoded_and_detached() {
        let jws = read(RFC7797).unwrap();

        let header = jws.decode_header().unwrap();

        assert_eq!(header.alg(), JwaSigningAlgorithm::Hs256);
        assert_eq!(header.encoding(), PayloadEncoding::Unencoded);
        assert!(jws.decode_payload().unwrap().is_detached());
        assert!(jws.decode_payload().unwrap().attached().is_none());

        // `header.`: what signs is that plus the payload the caller brings.
        assert!(jws.signing_prefix().ends_with('.'));
        assert_eq!(jws.signing_prefix().matches('.').count(), 1);

        // `b64` and `crit` are consumed, not left in `extra`.
        assert!(header.extra().is_empty());
    }

    #[test]
    fn the_raw_segments_are_the_ones_of_the_token() {
        let jws = JwsValidator::new(A1).unwrap();

        let mut segments = A1.split('.');

        assert_eq!(jws.header_b64(), segments.next().unwrap());
        assert_eq!(jws.payload_b64(), segments.next().unwrap());
        assert_eq!(jws.signature_b64(), segments.next().unwrap());

        // A detached payload is an empty segment.
        assert_eq!(JwsValidator::new(RFC7797).unwrap().payload_b64(), "");
    }

    #[test]
    fn what_is_decoded_is_decoded_once() {
        let jws = JwsValidator::new(A1).unwrap();

        // The second time it is the very same value, not another decoding of it.
        assert!(std::ptr::eq(
            jws.decode_header().unwrap(),
            jws.decode_header().unwrap()
        ));
        assert!(std::ptr::eq(
            jws.decode_payload().unwrap(),
            jws.decode_payload().unwrap()
        ));
        assert!(std::ptr::eq(
            jws.decode_signature().unwrap(),
            jws.decode_signature().unwrap()
        ));
    }

    #[test]
    fn errors_are_kept_too() {
        let jws = JwsValidator::new("!!!.cGF5.c2ln").unwrap();

        for _ in 0..2 {
            assert_eq!(
                jws.decode_header().err(),
                Some(JwsParseErrors::HeaderNotBase64Url)
            );

            // Payload and signature need the header, so they fail with its error.
            assert_eq!(
                jws.decode_payload().err(),
                Some(JwsParseErrors::HeaderNotBase64Url)
            );
            assert_eq!(
                jws.decode_signature().err(),
                Some(JwsParseErrors::HeaderNotBase64Url)
            );
        }
    }

    #[test]
    fn into_decoded_moves_what_was_read_and_reads_what_was_not() {
        // With the header and the payload already read.
        let jws = JwsValidator::new(A1).unwrap();

        jws.decode_header().unwrap();
        jws.decode_payload().unwrap();

        let (header, payload) = jws.into_decoded().unwrap();

        assert_eq!(header.typ(), Some("JWT"));
        assert!(payload.attached().is_some());

        // With nothing read yet.
        let (header, payload) = JwsValidator::new(A1).unwrap().into_decoded().unwrap();

        assert_eq!(header.typ(), Some("JWT"));
        assert!(payload.attached().is_some());

        // And an error is an error either way.
        assert_eq!(
            JwsValidator::new("!!!.cGF5.c2ln")
                .unwrap()
                .into_decoded()
                .err(),
            Some(JwsParseErrors::HeaderNotBase64Url)
        );
    }

    #[test]
    fn new_only_splits_and_the_rest_is_read_on_demand() {
        // The header is not even base64url, and `new` doesn't care.
        let jws = JwsValidator::new("!!!.cGF5.c2ln").unwrap();

        assert_eq!(
            jws.decode_header().err(),
            Some(JwsParseErrors::HeaderNotBase64Url)
        );

        // And a good header can be read without the payload or the signature being fine.
        let token = format!("{}.a.", base64url::encode(br#"{"alg":"HS256","kid":"k"}"#));

        let jws = JwsValidator::new(&token).unwrap();

        assert_eq!(jws.decode_header().unwrap().kid(), Some("k"));
        assert_eq!(
            jws.decode_payload().err(),
            Some(JwsParseErrors::PayloadNotBase64Url)
        );
        assert_eq!(
            jws.decode_signature().err(),
            Some(JwsParseErrors::SignatureLength)
        );
    }

    #[test]
    fn decode_payload_reads_the_header_for_b64() {
        let jws = JwsValidator::new(A1).unwrap();

        assert!(jws.decode_payload().unwrap().attached().is_some());

        let header = base64url::encode(br#"{"alg":"HS256","b64":false,"crit":["b64"]}"#);

        let token = format!("{header}.cGF5.{SIG32}");

        assert_eq!(
            JwsValidator::new(&token).unwrap().decode_payload().err(),
            Some(JwsParseErrors::UnencodedAttachedPayload)
        );
    }

    #[test]
    fn unencoded_payload_with_a_dot_inside_the_token_is_refused() {
        // The header and signature of RFC 7797 §4.2 with the payload `$.02` put inside the
        // token. The dot makes it four segments, so it is not a compact JWS (§5.2).
        let attached = "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19.$.02.\
            A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY";

        assert_eq!(
            JwsValidator::new(attached).err(),
            Some(JwsParseErrors::NotCompactSerialization)
        );
    }

    #[test]
    fn unknown_members_are_kept_in_extra() {
        accepted(
            r#"{"alg":"HS256","kid":"k","foo":1,"jku":"https://e.example"}"#,
            |jws| {
                let header = jws.decode_header().unwrap();

                assert_eq!(header.kid(), Some("k"));
                assert_eq!(header.extra()["foo"], json!(1));
                assert_eq!(header.extra()["jku"], json!("https://e.example"));
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
                let header = jws.decode_header().unwrap();

                assert_eq!(header.encoding(), PayloadEncoding::Base64Url);
                assert!(header.extra().is_empty());
            });
        }
    }

    #[test]
    fn token_shape() {
        for input in ["", "a", "a.b", "a.b.c.d", "...", "a.b.c.d.e"] {
            assert_eq!(
                JwsValidator::new(input).err(),
                Some(JwsParseErrors::NotCompactSerialization),
                "{input:?}"
            );
        }

        // Three empty segments do have the shape; they fail on the empty header instead.
        assert_eq!(read("..").err(), Some(JwsParseErrors::HeaderNotJson));
    }

    #[test]
    fn size_caps() {
        let huge = "a".repeat(MAX_TOKEN_LEN + 1);

        assert_eq!(
            JwsValidator::new(&huge).err(),
            Some(JwsParseErrors::TokenTooLarge)
        );

        let big_header = "a".repeat(base64url::encoded_len(MAX_HEADER_LEN) + 1);

        assert_eq!(
            read(&format!("{big_header}.cGF5.{SIG32}")).err(),
            Some(JwsParseErrors::HeaderTooLarge)
        );
    }

    #[test]
    fn header_is_not_base64url_or_not_json_or_not_an_object() {
        use JwsParseErrors::*;

        assert_eq!(
            read(&format!("a+b=.cGF5.{SIG32}")).err(),
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
            read(&format!("{header}.cGF5.{SIG32}")).err(),
            Some(JwsParseErrors::UnencodedAttachedPayload)
        );
    }

    #[test]
    fn detached_payload_with_base64url_encoding_is_accepted() {
        let header = base64url::encode(br#"{"alg":"HS256"}"#);

        let token = format!("{header}..{SIG32}");

        assert!(
            read(&token)
                .unwrap()
                .decode_payload()
                .unwrap()
                .is_detached()
        );
    }

    #[test]
    fn payload_with_an_impossible_length_or_characters() {
        let header = base64url::encode(br#"{"alg":"HS256"}"#);

        // A length of 1 (mod 4) can't come out of any encoder; `+` is not base64url; `Zh` has
        // unused bits set.
        for payload in ["a", "Zm+v", "Zh"] {
            assert_eq!(
                read(&format!("{header}.{payload}.{SIG32}")).err(),
                Some(JwsParseErrors::PayloadNotBase64Url),
                "{payload}"
            );
        }
    }

    #[test]
    fn signature_length_is_checked_against_alg() {
        let header = base64url::encode(br#"{"alg":"HS256"}"#);

        let longer = format!("{SIG32}AA");

        for signature in ["", "a", &SIG32[..SIG32.len() - 1], &longer] {
            assert_eq!(
                read(&format!("{header}.cGF5.{signature}")).err(),
                Some(JwsParseErrors::SignatureLength),
                "{signature:?}"
            );
        }

        // HS512 wants 64 bytes: the 32-byte signature of HS256 is refused.
        let header = base64url::encode(br#"{"alg":"HS512"}"#);

        assert_eq!(
            read(&format!("{header}.cGF5.{SIG32}")).err(),
            Some(JwsParseErrors::SignatureLength)
        );
    }

    #[test]
    fn signature_has_to_be_canonical_base64url() {
        let header = base64url::encode(br#"{"alg":"HS256"}"#);

        // The length of a real HS256 signature: one char is not base64url, and the last one
        // carries 4 unused bits that have to be zero.
        let bad_char = SIG32.replacen('-', "+", 1);
        let non_canonical = format!("{}l", &SIG32[..SIG32.len() - 1]);

        assert!(SIG32.ends_with('k'));

        for signature in [bad_char, non_canonical] {
            assert_eq!(
                read(&format!("{header}.cGF5.{signature}")).err(),
                Some(JwsParseErrors::SignatureNotBase64Url),
                "{signature}"
            );
        }
    }

    #[test]
    fn rsa_signature_only_has_to_be_non_empty() {
        let header = base64url::encode(br#"{"alg":"RS256"}"#);

        assert!(read(&format!("{header}.cGF5.{SIG32}")).is_ok());

        assert_eq!(
            read(&format!("{header}.cGF5.")).err(),
            Some(JwsParseErrors::SignatureLength)
        );
    }

    #[test]
    fn crit_set_is_closed_by_default_but_the_parameter_works() {
        let header = base64url::encode(br#"{"alg":"HS256","x":1,"crit":["x"]}"#);

        let token = format!("{header}.cGF5.{SIG32}");

        let jws = JwsValidator::new(&token).unwrap();

        assert_eq!(
            jws.decode_header().err(),
            Some(JwsParseErrors::CritUnsupported("x".into()))
        );

        assert!(UnverifiedHeader::decode(jws.header_b64(), &["x"]).is_ok());
    }

    #[test]
    fn is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<JwsValidator<'static>>();
    }
}
