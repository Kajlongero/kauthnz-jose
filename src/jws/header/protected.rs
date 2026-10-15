use serde::Serialize;

use serde::Serializer;

use serde::ser::SerializeMap;

use serde_json::Value;

use crate::jwa::JwaSigningAlgorithm;

use crate::jws::constants::MAX_HEADER_LEN;

use crate::jws::errors::JwsSigningErrors;

use crate::jws::validators::validate_extra;

use super::payload_encoding::PayloadEncoding;

/// The protected header of a JWS being signed (RFC 7515 §4), borrowed from the builder.
///
/// It can only be turned into JSON through [`to_json`](Self::to_json), which checks the custom
/// parameters first, so no unchecked header is ever written.
pub(in crate::jws) struct ProtectedHeader<'a> {
    pub alg: JwaSigningAlgorithm,

    pub encoding: PayloadEncoding,

    pub typ: Option<&'a str>,

    pub cty: Option<&'a str>,

    pub kid: Option<&'a str>,

    pub jku: Option<&'a str>,

    pub x5u: Option<&'a str>,

    pub x5c: &'a [String],

    pub x5t: Option<&'a str>,

    pub x5t_s256: Option<&'a str>,

    pub extra: &'a [(String, Value)],
}

impl ProtectedHeader<'_> {
    /// Validates the custom parameters and serializes the header, capped at `MAX_HEADER_LEN`.
    pub fn to_json(&self) -> Result<Vec<u8>, JwsSigningErrors> {
        validate_extra(self.extra)?;

        let json = serde_json::to_vec(self).map_err(|_| JwsSigningErrors::HeaderSerialization)?;

        if json.len() > MAX_HEADER_LEN {
            return Err(JwsSigningErrors::HeaderTooLarge);
        }

        Ok(json)
    }
}

// Written by hand so the order is explicit: `alg`, then `b64` and `crit` (as in the example of
// RFC 7797 §4.2), the registered parameters, and the custom ones in insertion order.
impl Serialize for ProtectedHeader<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;

        map.serialize_entry("alg", &self.alg)?;

        if self.encoding == PayloadEncoding::Unencoded {
            map.serialize_entry("b64", &false)?;
            map.serialize_entry("crit", &["b64"])?;
        }

        if let Some(typ) = self.typ {
            map.serialize_entry("typ", typ)?;
        }

        if let Some(cty) = self.cty {
            map.serialize_entry("cty", cty)?;
        }

        if let Some(kid) = self.kid {
            map.serialize_entry("kid", kid)?;
        }

        if let Some(jku) = self.jku {
            map.serialize_entry("jku", jku)?;
        }

        if let Some(x5u) = self.x5u {
            map.serialize_entry("x5u", x5u)?;
        }

        if !self.x5c.is_empty() {
            map.serialize_entry("x5c", self.x5c)?;
        }

        if let Some(x5t) = self.x5t {
            map.serialize_entry("x5t", x5t)?;
        }

        if let Some(x5t_s256) = self.x5t_s256 {
            map.serialize_entry("x5t#S256", x5t_s256)?;
        }

        for (name, value) in self.extra {
            map.serialize_entry(name, value)?;
        }

        map.end()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::base64url;

    use super::*;

    fn bare(alg: JwaSigningAlgorithm, encoding: PayloadEncoding) -> ProtectedHeader<'static> {
        ProtectedHeader {
            alg,
            encoding,
            typ: None,
            cty: None,
            kid: None,
            jku: None,
            x5u: None,
            x5c: &[],
            x5t: None,
            x5t_s256: None,
            extra: &[],
        }
    }

    fn json_of(header: &ProtectedHeader) -> String {
        String::from_utf8(header.to_json().unwrap()).unwrap()
    }

    #[test]
    fn only_alg_when_nothing_else_is_set() {
        let header = bare(JwaSigningAlgorithm::Hs256, PayloadEncoding::Base64Url);

        assert_eq!(json_of(&header), r#"{"alg":"HS256"}"#);
    }

    #[test]
    fn b64_true_is_never_written() {
        // RFC 7797 §3: `true` is the default, so the header has neither `b64` nor `crit`.
        let json = json_of(&bare(
            JwaSigningAlgorithm::Hs256,
            PayloadEncoding::Base64Url,
        ));

        assert!(!json.contains("b64"));
        assert!(!json.contains("crit"));
    }

    #[test]
    fn rfc7797_section_4_2_header() {
        let header = bare(JwaSigningAlgorithm::Hs256, PayloadEncoding::Unencoded);

        let json = header.to_json().unwrap();

        assert_eq!(json, br#"{"alg":"HS256","b64":false,"crit":["b64"]}"#);

        // The same header as it appears, encoded, in the example of RFC 7797 §4.2.
        assert_eq!(
            base64url::encode(&json),
            "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19"
        );
    }

    #[test]
    fn every_parameter_in_a_fixed_order() {
        let x5c = vec!["MIIB".to_string(), "MIIC".to_string()];
        let extra = vec![
            ("foo".to_string(), json!(1)),
            ("bar".to_string(), json!("x")),
        ];

        let header = ProtectedHeader {
            alg: JwaSigningAlgorithm::Hs256,
            encoding: PayloadEncoding::Unencoded,
            typ: Some("at+jwt"),
            cty: Some("JWT"),
            kid: Some("k1"),
            jku: Some("https://e.example/jwks"),
            x5u: Some("https://e.example/cert"),
            x5c: &x5c,
            x5t: Some("t1"),
            x5t_s256: Some("t2"),
            extra: &extra,
        };

        assert_eq!(
            json_of(&header),
            concat!(
                r#"{"alg":"HS256","b64":false,"crit":["b64"],"typ":"at+jwt","cty":"JWT","#,
                r#""kid":"k1","jku":"https://e.example/jwks","x5u":"https://e.example/cert","#,
                r#""x5c":["MIIB","MIIC"],"x5t":"t1","x5t#S256":"t2","foo":1,"bar":"x"}"#,
            )
        );
    }

    #[test]
    fn empty_x5c_is_omitted() {
        let mut header = bare(JwaSigningAlgorithm::Hs256, PayloadEncoding::Base64Url);

        header.typ = Some("JWT");

        assert_eq!(json_of(&header), r#"{"alg":"HS256","typ":"JWT"}"#);
    }

    #[test]
    fn alg_is_written_with_its_registered_name() {
        for (alg, name) in [
            (JwaSigningAlgorithm::Hs256, "HS256"),
            (JwaSigningAlgorithm::Hs384, "HS384"),
            (JwaSigningAlgorithm::Hs512, "HS512"),
        ] {
            let header = bare(alg, PayloadEncoding::Base64Url);

            assert_eq!(json_of(&header), format!(r#"{{"alg":"{name}"}}"#));
        }
    }

    #[test]
    fn custom_parameters_are_validated_before_writing() {
        for (extra, error) in [
            (
                vec![("alg".to_string(), json!("none"))],
                JwsSigningErrors::ReservedHeaderParam("alg".to_string()),
            ),
            (
                vec![("b64".to_string(), json!(false))],
                JwsSigningErrors::ReservedHeaderParam("b64".to_string()),
            ),
            (
                vec![("a".to_string(), json!(1)), ("a".to_string(), json!(2))],
                JwsSigningErrors::DuplicateHeaderParam("a".to_string()),
            ),
            (
                vec![(String::new(), json!(1))],
                JwsSigningErrors::EmptyHeaderParamName,
            ),
            (
                vec![("a\0".to_string(), json!(1))],
                JwsSigningErrors::ControlCharInHeaderParamName("a\0".to_string()),
            ),
        ] {
            let mut header = bare(JwaSigningAlgorithm::Hs256, PayloadEncoding::Base64Url);

            header.extra = &extra;

            assert_eq!(header.to_json(), Err(error));
        }
    }

    #[test]
    fn a_header_over_the_cap_is_refused() {
        let big = vec![("big".to_string(), json!("a".repeat(MAX_HEADER_LEN)))];

        let mut header = bare(JwaSigningAlgorithm::Hs256, PayloadEncoding::Base64Url);

        header.extra = &big;

        assert_eq!(header.to_json(), Err(JwsSigningErrors::HeaderTooLarge));
    }

    #[test]
    fn a_header_at_the_cap_is_accepted() {
        let overhead = r#"{"alg":"HS256","big":""}"#.len();

        let fits = vec![(
            "big".to_string(),
            json!("a".repeat(MAX_HEADER_LEN - overhead)),
        )];

        let mut header = bare(JwaSigningAlgorithm::Hs256, PayloadEncoding::Base64Url);

        header.extra = &fits;

        assert_eq!(header.to_json().unwrap().len(), MAX_HEADER_LEN);
    }

    #[test]
    fn output_parses_back_to_the_same_values() {
        let x5c = vec!["MIIB".to_string()];
        let extra = vec![("n".to_string(), json!({"a": [1, 2, null]}))];

        let mut header = bare(JwaSigningAlgorithm::Hs512, PayloadEncoding::Unencoded);

        header.kid = Some("a\"b\\c/😀");
        header.x5c = &x5c;
        header.extra = &extra;

        let parsed: Value = serde_json::from_slice(&header.to_json().unwrap()).unwrap();

        assert_eq!(
            parsed,
            json!({
                "alg": "HS512",
                "b64": false,
                "crit": ["b64"],
                "kid": "a\"b\\c/😀",
                "x5c": ["MIIB"],
                "n": {"a": [1, 2, null]},
            })
        );
    }
}
