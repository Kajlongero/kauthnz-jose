#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JsonErrors {
    /// The input is longer than the cap the caller passed.
    TooLarge,

    /// Not valid JSON: syntax, invalid UTF-8, a lone surrogate, bytes after the value, or
    /// nesting deeper than the limit of the parser.
    Malformed,

    /// Valid JSON, but the top level is not an object.
    NotAnObject,

    /// Member names that appear more than once in the top-level object, each listed once and
    /// in the order of their first repetition (RFC 7515 §4, RFC 8259 §4). Never empty.
    DuplicateMembers(Vec<String>),
}
