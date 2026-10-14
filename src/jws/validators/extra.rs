use std::collections::HashSet;

use serde_json::Value;

use crate::jws::errors::JwsSigningErrors;

use crate::jws::constants::RESERVED_HEADER_PARAMS;

/// Checks the custom header parameters before they are merged into the protected header.
pub(in crate::jws) fn validate_extra(extra: &[(String, Value)]) -> Result<(), JwsSigningErrors> {
    let mut seen = HashSet::with_capacity(extra.len());

    for (name, _) in extra {
        if name.is_empty() {
            return Err(JwsSigningErrors::EmptyHeaderParamName);
        }

        if name.chars().any(char::is_control) {
            return Err(JwsSigningErrors::ControlCharInHeaderParamName(name.clone()));
        }

        if RESERVED_HEADER_PARAMS.contains(&name.as_str()) {
            return Err(JwsSigningErrors::ReservedHeaderParam(name.clone()));
        }

        if !seen.insert(name.as_str()) {
            return Err(JwsSigningErrors::DuplicateHeaderParam(name.clone()));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn params(names: &[&str]) -> Vec<(String, Value)> {
        names
            .iter()
            .map(|name| (name.to_string(), json!("v")))
            .collect()
    }

    #[test]
    fn accepts_unique_custom_names() {
        assert_eq!(validate_extra(&[]), Ok(()));
        assert_eq!(validate_extra(&params(&["foo", "bar", "x-trace"])), Ok(()));
    }

    #[test]
    fn rejects_every_name_registered_for_jws() {
        // RFC 7515 §4.1.1 to §4.1.11, written out on purpose and not read from the constant,
        // so a name dropped from `RESERVED_HEADER_PARAMS` fails here.
        let registered = [
            "alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit",
        ];

        for name in registered {
            assert_eq!(
                validate_extra(&params(&[name])),
                Err(JwsSigningErrors::ReservedHeaderParam(name.to_string())),
                "{name}"
            );
        }
    }

    #[test]
    fn rejects_b64() {
        // RFC 7797 §3: the library writes it, together with `crit`, only in `sign_unencoded`.
        assert_eq!(
            validate_extra(&params(&["b64"])),
            Err(JwsSigningErrors::ReservedHeaderParam("b64".to_string()))
        );
    }

    #[test]
    fn rejects_names_defined_for_jwe_and_jwa() {
        // RFC 7516 §4.1.2 and §4.1.3 (`enc`, `zip`); RFC 7518 §4.6.1 (`epk`, `apu`, `apv`),
        // §4.7.1 (`iv`, `tag`) and §4.8.1 (`p2s`, `p2c`).
        let jwe = ["enc", "zip", "epk", "apu", "apv", "iv", "tag", "p2s", "p2c"];

        for name in jwe {
            assert_eq!(
                validate_extra(&params(&[name])),
                Err(JwsSigningErrors::ReservedHeaderParam(name.to_string())),
                "{name}"
            );
        }
    }

    #[test]
    fn rejects_duplicates() {
        // RFC 7515 §4: header parameter names within the JOSE header MUST be unique.
        assert_eq!(
            validate_extra(&params(&["foo", "bar", "foo"])),
            Err(JwsSigningErrors::DuplicateHeaderParam("foo".to_string()))
        );
    }

    #[test]
    fn duplicates_are_rejected_whatever_the_value() {
        let extra = vec![("foo".to_string(), json!(1)), ("foo".to_string(), json!(1))];

        assert_eq!(
            validate_extra(&extra),
            Err(JwsSigningErrors::DuplicateHeaderParam("foo".to_string()))
        );
    }

    #[test]
    fn rejects_empty_name() {
        assert_eq!(
            validate_extra(&params(&["foo", ""])),
            Err(JwsSigningErrors::EmptyHeaderParamName)
        );
    }

    #[test]
    fn names_are_compared_exactly() {
        // JSON member names are case-sensitive and compared code unit by code unit
        // (RFC 8259 §8.3), so `Alg` is a different name from `alg` and is not reserved.
        assert_eq!(validate_extra(&params(&["Alg", "KID", "B64"])), Ok(()));
    }

    #[test]
    fn rejects_control_characters_in_names() {
        // NUL, the rest of C0, DEL and C1. All are valid JSON once escaped (RFC 8259 §7), the
        // library refuses them anyway.
        for name in [
            "a\0b", "\0", "a\nb", "a\tb", "a\r", "\u{1f}", "\u{7f}", "\u{80}", "\u{9f}",
        ] {
            assert_eq!(
                validate_extra(&params(&[name])),
                Err(JwsSigningErrors::ControlCharInHeaderParamName(
                    name.to_string()
                )),
                "{name:?}"
            );
        }
    }

    #[test]
    fn accepts_unicode_names() {
        // Two-byte, three-byte and four-byte (astral, a surrogate pair in JSON escapes) UTF-8,
        // plus U+2028 and U+2029, which are legal in JSON strings and are not control chars.
        for name in ["ñ", "名前", "😀", "a\u{2028}b", "a\u{2029}b", "\u{a0}"] {
            assert_eq!(validate_extra(&params(&[name])), Ok(()), "{name:?}");
        }
    }

    #[test]
    fn canonically_equivalent_names_are_different_names() {
        // "é" as one code point (NFC) and as "e" + combining acute (NFD). JSON compares code
        // unit by code unit with no normalization (RFC 8259 §8.3), so they are not duplicates.
        assert_eq!(validate_extra(&params(&["\u{e9}", "e\u{301}"])), Ok(()));
    }

    #[test]
    fn lookalike_of_a_reserved_name_is_not_reserved() {
        // Cyrillic "а" (U+0430) instead of Latin "a". Not the same name, so it passes; telling
        // lookalikes apart is not this function's job.
        assert_eq!(validate_extra(&params(&["\u{430}lg"])), Ok(()));
    }

    #[test]
    fn names_that_need_escaping_survive_a_json_round_trip() {
        // Quote, backslash, slash and a lone-looking astral char: whatever `serde_json` writes
        // has to parse back to the same names and values, with no loss or merge.
        let extra: Vec<(String, Value)> = ["a\"b", "a\\b", "a/b", "😀", "\u{2028}", "x y", "{}"]
            .iter()
            .enumerate()
            .map(|(i, name)| (name.to_string(), json!(i)))
            .collect();

        assert_eq!(validate_extra(&extra), Ok(()));

        let object: serde_json::Map<String, Value> = extra.iter().cloned().collect();

        assert_eq!(object.len(), extra.len());

        let text = serde_json::to_string(&object).unwrap();
        let back: Value = serde_json::from_str(&text).unwrap();

        assert_eq!(back, Value::Object(object));
    }

    #[test]
    fn control_characters_in_values_are_escaped_not_rejected() {
        // The value is always valid JSON, a NUL inside a string is just escaped as \u0000.
        let extra = vec![("note".to_string(), json!("a\0b\n\u{7f}"))];

        assert_eq!(validate_extra(&extra), Ok(()));

        let text = serde_json::to_string(&extra[0].1).unwrap();

        assert!(text.contains("\\u0000"));
        assert!(!text.contains('\0'));
        assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), extra[0].1);
    }

    #[test]
    fn non_finite_floats_become_null_before_reaching_the_builder() {
        // `Value::from(f64::NAN)` is `Null` and `Number::from_f64` is `None`: the library
        // can't see a NaN, so the only safe way to pass a float is `Number::from_f64`.
        assert_eq!(Value::from(f64::NAN), Value::Null);
        assert_eq!(Value::from(f64::INFINITY), Value::Null);
        assert!(serde_json::Number::from_f64(f64::NAN).is_none());
        assert!(serde_json::Number::from_f64(1.5).is_some());
    }

    #[test]
    fn the_value_does_not_matter() {
        let extra = vec![
            ("a".to_string(), Value::Null),
            ("b".to_string(), json!({"nested": [1, 2, 3]})),
        ];

        assert_eq!(validate_extra(&extra), Ok(()));
    }
}
