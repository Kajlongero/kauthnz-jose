/// Compares the `typ` or `cty` of a token with the one that is expected (RFC 7515 §4.1.9,
/// §4.1.10).
///
/// Media type names are case-insensitive, and the `application/` prefix may be left out, so a
/// receiver has to take both forms (RFC 7515 §4.1.9). It is dropped from both sides, and what is
/// left is compared without regard to case.
pub(in crate::jws) fn media_type_matches(actual: &str, expected: &str) -> bool {
    fn bare(value: &str) -> &str {
        const PREFIX: &str = "application/";

        match value.get(..PREFIX.len()) {
            // `get` and not `[..]`: nothing here can panic, whatever the bytes are.
            Some(start) if start.eq_ignore_ascii_case(PREFIX) => {
                value.get(PREFIX.len()..).unwrap_or(value)
            }

            _ => value,
        }
    }

    bare(actual).eq_ignore_ascii_case(bare(expected))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_value_matches() {
        assert!(media_type_matches("at+jwt", "at+jwt"));
        assert!(media_type_matches("JWT", "JWT"));
    }

    #[test]
    fn case_is_ignored() {
        assert!(media_type_matches("AT+JWT", "at+jwt"));
        assert!(media_type_matches("at+jwt", "At+Jwt"));
    }

    #[test]
    fn application_prefix_is_optional_on_either_side() {
        assert!(media_type_matches("application/at+jwt", "at+jwt"));
        assert!(media_type_matches("at+jwt", "application/at+jwt"));
        assert!(media_type_matches("APPLICATION/AT+JWT", "application/at+jwt"));
    }

    #[test]
    fn different_values_do_not_match() {
        assert!(!media_type_matches("at+jwt", "JWT"));
        assert!(!media_type_matches("at+jwt ", "at+jwt"));
        assert!(!media_type_matches("", "at+jwt"));

        // Only the prefix is dropped, not any other type.
        assert!(!media_type_matches("text/at+jwt", "at+jwt"));
        assert!(!media_type_matches("application/application/at+jwt", "at+jwt"));
    }

    #[test]
    fn short_or_non_ascii_values_do_not_panic() {
        assert!(!media_type_matches("app", "at+jwt"));
        assert!(!media_type_matches("applicatio\u{e9}/x", "x"));
        assert!(!media_type_matches("😀😀😀😀😀😀😀", "x"));

        // Byte 12 (the end of the prefix) falls in the middle of an emoji: `get` says `None`
        // for a cut that is not on a character boundary, and it is not sliced.
        assert!(!media_type_matches("applicati😀", "x"));
        assert!(!media_type_matches("applicati😀", "applicati😀x"));
        assert!(media_type_matches("applicati😀", "APPLICATI😀"));

        // Every cut position of a multi-byte string, as the actual and as the expected.
        // Including sequences of several code points: a family emoji, a flag, a keycap.
        for text in [
            "aé😀b",
            "👨\u{200d}👩\u{200d}👧\u{200d}👦",
            "🇨🇴",
            "1\u{fe0f}\u{20e3}",
        ] {
            for end in 0..=text.len() {
                if let Some(part) = text.get(..end) {
                    assert!(media_type_matches(part, part));
                    assert!(!media_type_matches(part, "x"));
                }
            }

            // With `application/` in front, only the prefix is dropped.
            let prefixed = format!("application/{text}");

            assert!(media_type_matches(&prefixed, text));
            assert!(media_type_matches(text, &prefixed));
        }
    }
}
