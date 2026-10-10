#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Base64Errors {
    Encoding(Base64EncodingErrors),

    Decoding(Base64DecodingErrors),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64EncodingErrors {
    /// The output buffer is shorter than `encoded_len(input.len())`.
    InvalidOutputLength,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64DecodingErrors {
    /// The input length is `1 (mod 4)`, which no encoder can produce.
    InvalidLength,

    /// A byte outside the base64url alphabet (`A-Z a-z 0-9 - _`).
    InvalidCharacter,

    /// The output buffer is shorter than `decoded_len(input.len())`.
    InvalidOutputLength,

    /// A trailing `=`: JOSE uses base64url with the padding omitted (RFC 7515 §2).
    DisallowedPadding,

    /// The last character has non-zero unused bits, e.g. `"Zh"` where `"Zg"` is the only
    /// valid encoding of `b"f"` (RFC 4648 §3.5). Rejecting these leaves one accepted encoding
    /// per byte string, so a JWS signature segment can't be rewritten into a second token
    /// that still verifies.
    NonCanonical,
}

impl From<Base64EncodingErrors> for Base64Errors {
    fn from(value: Base64EncodingErrors) -> Self {
        Self::Encoding(value)
    }
}

impl From<Base64DecodingErrors> for Base64Errors {
    fn from(value: Base64DecodingErrors) -> Self {
        Self::Decoding(value)
    }
}
