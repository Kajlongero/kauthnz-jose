/// Literal value of the `typ` header parameter for a token type (RFC 7515 §4.1.9).
///
/// Implemented by a marker type, usually a unit struct, and used by both sides: the builder
/// writes `T::TYP` into the header and the verifier requires it when reading one. The literal
/// lives in a single place, so signing and verification can't drift apart.
///
/// ```ignore
/// struct AccessTokenType;
///
/// impl TokenType for AccessTokenType {
///     const TYP: &'static str = "at+jwt";
/// }
/// ```
pub trait TokenType {
    const TYP: &'static str;
}
