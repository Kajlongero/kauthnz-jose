use base64ct::Base64UrlUnpadded;
use base64ct::Encoding;

use super::errors::Base64DecodingErrors;

/// Exact length, in bytes, of the decoding of `input_len` unpadded base64url chars.
///
/// A length of `1 (mod 4)` can't come out of any encoder, so it's rejected here.
pub(crate) const fn decoded_len(input_len: usize) -> Result<usize, Base64DecodingErrors> {
    match input_len % 4 {
        1 => Err(Base64DecodingErrors::InvalidLength),

        remanent => Ok(input_len / 4 * 3 + remanent.saturating_sub(1)),
    }
}

/// Decodes unpadded base64url into a new `Vec`.
///
/// Fine for headers, payloads, signatures and public key parameters. For secrets (`d`, `p`,
/// `q`, `k`, ...) use [`decode_into`] with a buffer you zeroize: if decoding fails here, the
/// `Vec` may hold partially decoded bytes and is freed without being wiped.
pub(crate) fn decode(b64_str: &str) -> Result<Vec<u8>, Base64DecodingErrors> {
    let mut out = vec![0u8; decoded_len(b64_str.len())?];

    decode_into(b64_str, &mut out)?;

    Ok(out)
}

/// Decodes unpadded base64url into `out` and returns the written prefix.
///
/// `out` must hold at least `decoded_len(b64_str.len())` bytes; on error it may contain
/// partially decoded data. Constant time with respect to the *contents* of the input: the
/// only things it branches on are the length (public anyway) and the error it returns.
pub(crate) fn decode_into<'o>(
    b64_str: &str,
    out: &'o mut [u8],
) -> Result<&'o [u8], Base64DecodingErrors> {
    let src = b64_str.as_bytes();

    // Padding can only be trailing, so the last byte is all we need to look at.
    if src.last() == Some(&b'=') {
        return Err(Base64DecodingErrors::DisallowedPadding);
    }

    let len = decoded_len(src.len())?;

    let out = out
        .get_mut(..len)
        .ok_or(Base64DecodingErrors::InvalidOutputLength)?;

    Base64UrlUnpadded::decode(src, out).map_err(|err| match err {
        base64ct::Error::InvalidLength => Base64DecodingErrors::InvalidOutputLength,
        // base64ct reports out-of-alphabet bytes and non-zero unused bits the same way.
        _ => classify_invalid_encoding(src),
    })
}

/// Splits base64ct's `InvalidEncoding` into `NonCanonical` vs `InvalidCharacter`.
///
/// Only runs on the error path and only reads the last byte; the single branch is on the
/// resulting classification, which is handed back to the caller anyway.
fn classify_invalid_encoding(src: &[u8]) -> Base64DecodingErrors {
    // Unused low bits of the last sextet: a 2-char tail carries 4 of them, a 3-char tail 2.
    let unused_bits: i16 = match src.len() % 4 {
        2 => 0b1111,
        3 => 0b0011,
        _ => return Base64DecodingErrors::InvalidCharacter,
    };

    let sextet = decode_sextet(src[src.len() - 1]);

    // `&` instead of `&&` so there's no early exit on whether the character is valid.
    if (sextet >= 0) & ((sextet & unused_bits) != 0) {
        Base64DecodingErrors::NonCanonical
    } else {
        Base64DecodingErrors::InvalidCharacter
    }
}

/// Value (0..=63) of a base64url character, or -1 if it isn't one, without branches or tables.
///
/// Each line only contributes when `c` is inside its range: `(lo - c) & (c - hi)`, with `lo`
/// and `hi` just outside the range, is negative exactly then, and `>> 8` turns that sign into
/// an all-ones mask. Same trick base64ct uses internally.
fn decode_sextet(c: u8) -> i16 {
    let c = i16::from(c);

    let mut v: i16 = -1;

    v += (((0x40 - c) & (c - 0x5b)) >> 8) & (c - 64); // 'A'..='Z' -> 0..=25
    v += (((0x60 - c) & (c - 0x7b)) >> 8) & (c - 70); // 'a'..='z' -> 26..=51
    v += (((0x2f - c) & (c - 0x3a)) >> 8) & (c + 5); // '0'..='9' -> 52..=61
    v += (((0x2c - c) & (c - 0x2e)) >> 8) & 63; // '-' -> 62
    v += (((0x5e - c) & (c - 0x60)) >> 8) & 64; // '_' -> 63

    v
}
