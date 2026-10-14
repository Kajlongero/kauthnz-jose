/// Literal value of the `cty` header parameter for a payload content type (RFC 7515 §4.1.10).
///
/// A marker type carries the literal: the builder writes `T::CTY` and the verifier compares
/// against it. `cty` is an open media type, so the library doesn't define the values; the one
/// with a special meaning is `JWT`, required for a nested JWT (RFC 7519 §5.2).
///
/// ```ignore
/// struct NestedJwt;
///
/// impl ContentType for NestedJwt {
///     const CTY: &'static str = "JWT";
/// }
/// ```
pub trait ContentType {
    const CTY: &'static str;
}
