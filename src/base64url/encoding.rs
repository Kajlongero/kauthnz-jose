use base64ct::Encoding;

use base64ct::Base64UrlUnpadded;

use super::errors::Base64EncodingErrors;

/// Exact length, in chars, of the unpadded base64url encoding of `input_len` bytes.
///
/// `const` so it can size stack buffers, e.g. `[0u8; encoded_len(64)]` for an ES256 signature.
/// It can't overflow for any real slice length (`<= isize::MAX`).
pub(crate) const fn encoded_len(input_len: usize) -> usize {
    input_len / 3 * 4 + (input_len % 3 * 4 + 2) / 3
}

/// Encodes `bytes` as unpadded base64url, in constant time with respect to their contents.
///
/// For secrets (exporting a JWK's `d` or `k`), prefer [`encode_into`] with a buffer you
/// zeroize: this `String` won't be wiped when dropped.
pub(crate) fn encode(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// Encodes `bytes` into `out` without allocating and returns the written prefix as `&str`.
///
/// `out` must hold at least `encoded_len(bytes.len())` bytes.
pub(crate) fn encode_into<'o>(
    bytes: &[u8],
    out: &'o mut [u8],
) -> Result<&'o str, Base64EncodingErrors> {
    Base64UrlUnpadded::encode(bytes, out).map_err(|_| Base64EncodingErrors::InvalidOutputLength)
}
