mod errors;

mod decoding;

mod encoding;

pub(crate) use decoding::decode;
pub(crate) use decoding::decode_into;
pub(crate) use decoding::decoded_len;

pub(crate) use encoding::encode;
pub(crate) use encoding::encode_into;
pub(crate) use encoding::encoded_len;

pub(crate) use errors::Base64DecodingErrors;
pub(crate) use errors::Base64EncodingErrors;
pub(crate) use errors::Base64Errors;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        // RFC 4648 §10 with the padding stripped (the url alphabet only changes `+` and `/`).
        let vectors: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "Zg"),
            (b"fo", "Zm8"),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg"),
            (b"fooba", "Zm9vYmE"),
            (b"foobar", "Zm9vYmFy"),
        ];

        for (raw, b64) in vectors {
            assert_eq!(encode(raw), b64);
            assert_eq!(decode(b64).unwrap(), raw);
        }

        // 62 and 63, the two characters that differ from standard base64.
        assert_eq!(encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(decode("-_8").unwrap(), [0xfb, 0xff]);
    }

    #[test]
    fn lengths_match_real_output() {
        for n in 0..64 {
            let b64 = encode(&vec![0xa5; n]);

            assert_eq!(b64.len(), encoded_len(n));
            assert_eq!(decoded_len(b64.len()), Ok(n));
        }
    }

    #[test]
    fn decoding_errors() {
        use Base64DecodingErrors::*;

        assert_eq!(decode("Zg=="), Err(DisallowedPadding));
        assert_eq!(decode("Zm9vY"), Err(InvalidLength));
        assert_eq!(decode("Zm+v"), Err(InvalidCharacter));
        assert_eq!(decode("Z+"), Err(InvalidCharacter));
        assert_eq!(decode("Zh"), Err(NonCanonical));
        assert_eq!(decode("Zm9"), Err(NonCanonical));
        assert_eq!(decode_into("Zm9v", &mut [0u8; 2]), Err(InvalidOutputLength));
    }

    #[test]
    fn encoding_errors() {
        assert_eq!(
            encode_into(b"foo", &mut [0u8; 3]),
            Err(Base64EncodingErrors::InvalidOutputLength)
        );
    }

    #[test]
    fn question_mark_lifts_into_umbrella() {
        fn reencode(s: &str) -> Result<String, Base64Errors> {
            Ok(encode(&decode(s)?))
        }

        assert_eq!(
            reencode("Zg=="),
            Err(Base64Errors::Decoding(
                Base64DecodingErrors::DisallowedPadding
            ))
        );
    }
}
