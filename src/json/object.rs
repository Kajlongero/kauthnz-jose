use serde::de::DeserializeSeed;

use serde_json::Map;

use serde_json::Value;

use serde_json::error::Category;

use super::errors::JsonErrors;

use super::strict_map::StrictMap;

/// Parses `bytes` as a JSON object, refusing repeated member names.
///
/// `max_len` is checked before anything is parsed. When the input is both malformed and has
/// repeated names, the malformed error is the one returned.
pub(crate) fn parse_object(
    bytes: &[u8],
    max_len: usize,
) -> Result<Map<String, Value>, JsonErrors> {
    if bytes.len() > max_len {
        return Err(JsonErrors::TooLarge);
    }

    let mut duplicates = Vec::new();

    let mut de = serde_json::Deserializer::from_slice(bytes);

    let parsed = StrictMap {
        duplicates: &mut duplicates,
    }
    .deserialize(&mut de)
    .and_then(|map| de.end().map(|()| map));

    match parsed {
        Ok(map) if duplicates.is_empty() => Ok(map),

        Ok(_) => Err(JsonErrors::DuplicateMembers(duplicates)),

        // The syntax is fine and the value is not an object: serde_json reports the type
        // mismatch as a data error.
        Err(e) if e.classify() == Category::Data => Err(JsonErrors::NotAnObject),

        Err(_) => Err(JsonErrors::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const CAP: usize = 8 * 1024;

    fn parse(input: &[u8]) -> Result<Map<String, Value>, JsonErrors> {
        parse_object(input, CAP)
    }

    fn duplicates(names: &[&str]) -> Result<Map<String, Value>, JsonErrors> {
        Err(JsonErrors::DuplicateMembers(
            names.iter().map(|n| n.to_string()).collect(),
        ))
    }

    #[test]
    fn a_plain_object_parses() {
        let map = parse(br#"{"alg":"HS256","n":{"a":[1,null]}}"#).unwrap();

        assert_eq!(map["alg"], json!("HS256"));
        assert_eq!(map["n"], json!({"a": [1, null]}));
    }

    #[test]
    fn empty_object_parses() {
        assert!(parse(b"{}").unwrap().is_empty());
    }

    #[test]
    fn a_repeated_name_is_refused() {
        assert_eq!(parse(br#"{"a":1,"a":2}"#), duplicates(&["a"]));
    }

    #[test]
    fn every_repeated_name_is_reported_once() {
        assert_eq!(
            parse(br#"{"a":1,"b":1,"b":2,"a":2,"b":3,"c":1}"#),
            duplicates(&["b", "a"])
        );
    }

    #[test]
    fn names_are_compared_once_decoded() {
        // `a` is `a`.
        assert_eq!(parse(br#"{"a":1,"a":2}"#), duplicates(&["a"]));
    }

    #[test]
    fn names_are_case_sensitive() {
        assert!(parse(br#"{"a":1,"A":2}"#).is_ok());
    }

    #[test]
    fn repeats_in_nested_objects_are_not_checked() {
        assert!(parse(br#"{"a":{"b":1,"b":2}}"#).is_ok());
    }

    #[test]
    fn malformed_wins_over_duplicates() {
        assert_eq!(parse(br#"{"a":1,"a":2,"#), Err(JsonErrors::Malformed));
    }

    #[test]
    fn the_top_level_must_be_an_object() {
        for input in [&b"[]"[..], b"1", b"\"x\"", b"null", b"true"] {
            assert_eq!(parse(input), Err(JsonErrors::NotAnObject), "{input:?}");
        }
    }

    #[test]
    fn malformed_input() {
        for input in [
            &b""[..],
            b"{",
            b"{\"a\":}",
            // Bytes after the value.
            b"{} x",
            b"{}{}",
            // A raw control character inside a string, NUL included, has to be escaped.
            b"{\"a\":\"\0\"}",
            b"{\"a\":\"\n\"}",
            // Invalid UTF-8.
            b"{\"a\":\"\xff\"}",
            // Lone surrogates.
            br#"{"a":"\ud800"}"#,
            br#"{"\udc00":1}"#,
        ] {
            assert_eq!(parse(input), Err(JsonErrors::Malformed), "{input:?}");
        }
    }

    #[test]
    fn nesting_beyond_the_parser_limit_is_refused() {
        let deep = format!(r#"{{"a":{}{}}}"#, "[".repeat(200), "]".repeat(200));

        assert_eq!(parse(deep.as_bytes()), Err(JsonErrors::Malformed));

        let shallow = format!(r#"{{"a":{}{}}}"#, "[".repeat(10), "]".repeat(10));

        assert!(parse(shallow.as_bytes()).is_ok());
    }

    #[test]
    fn the_size_cap_is_checked_first() {
        let input = br#"{"a":1}"#;

        assert!(parse_object(input, input.len()).is_ok());
        assert_eq!(
            parse_object(input, input.len() - 1),
            Err(JsonErrors::TooLarge)
        );

        // Too large wins even when the input would not parse.
        assert_eq!(parse_object(b"not json", 3), Err(JsonErrors::TooLarge));
    }
}
