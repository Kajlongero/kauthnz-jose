use hmac::Mac;

use hmac::Hmac;

use hmac::KeyInit;

use sha2::Sha256;
use sha2::Sha384;
use sha2::Sha512;

use crate::jwa::JwaSigningAlgorithm;

use crate::jws::signers::Signer;

use crate::jws::signers::SignerErrors;

use crate::jws::signers::SignerKeyErrors;

/// The keyed MAC for each hash. The key lives only inside it: there is no copy of the raw
/// secret to keep around, and each signature starts from a clone of this state.
enum Keyed {
    Hs256(Hmac<Sha256>),

    Hs384(Hmac<Sha384>),

    Hs512(Hmac<Sha512>),
}

/// Signs with HS256, HS384 or HS512 (RFC 7518 §3.2).
pub struct HmacSigner {
    // The algorithm is not stored: `alg()` reads it from the variant, so what is reported in
    // the header and what is computed come from the same value and can't diverge.
    keyed: Keyed,
}

impl Keyed {
    fn new(alg: JwaSigningAlgorithm, secret: &[u8]) -> Result<Self, SignerKeyErrors> {
        fn mac<M: KeyInit>(alg: JwaSigningAlgorithm, secret: &[u8]) -> Result<M, SignerKeyErrors> {
            // For HS* the signature is as long as the hash output, the minimum key size.
            let min_key_len = alg
                .signature_len()
                .ok_or(SignerKeyErrors::AlgorithmMismatch)?;

            if secret.len() < min_key_len {
                return Err(SignerKeyErrors::TooShort);
            }

            // HMAC takes a key of any length, so past the check above this can't fail.
            M::new_from_slice(secret).map_err(|_| SignerKeyErrors::Invalid)
        }

        // The catch-all only refuses: nothing that is not HS* gets built.
        Ok(match alg {
            JwaSigningAlgorithm::Hs256 => Self::Hs256(mac(alg, secret)?),

            JwaSigningAlgorithm::Hs384 => Self::Hs384(mac(alg, secret)?),

            JwaSigningAlgorithm::Hs512 => Self::Hs512(mac(alg, secret)?),

            _ => return Err(SignerKeyErrors::AlgorithmMismatch),
        })
    }

    fn alg(&self) -> JwaSigningAlgorithm {
        match self {
            Self::Hs256(_) => JwaSigningAlgorithm::Hs256,

            Self::Hs384(_) => JwaSigningAlgorithm::Hs384,

            Self::Hs512(_) => JwaSigningAlgorithm::Hs512,
        }
    }

    fn tag(&self, signing_input: &[u8]) -> Vec<u8> {
        fn finish<M: Mac + Clone>(keyed: &M, signing_input: &[u8]) -> Vec<u8> {
            let mut mac = keyed.clone();

            mac.update(signing_input);

            mac.finalize().into_bytes().to_vec()
        }

        match self {
            Self::Hs256(mac) => finish(mac, signing_input),

            Self::Hs384(mac) => finish(mac, signing_input),

            Self::Hs512(mac) => finish(mac, signing_input),
        }
    }
}

impl HmacSigner {
    /// The key has to be at least as long as the hash output: 32, 48 or 64 bytes for HS256,
    /// HS384 or HS512 (RFC 7518 §3.2). A longer key is fine. Its entropy can't be checked.
    pub fn new(alg: JwaSigningAlgorithm, secret: &[u8]) -> Result<Self, SignerKeyErrors> {
        Ok(Self {
            keyed: Keyed::new(alg, secret)?,
        })
    }
}

impl Signer for HmacSigner {
    fn alg(&self) -> JwaSigningAlgorithm {
        self.keyed.alg()
    }

    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, SignerErrors> {
        Ok(self.keyed.tag(signing_input))
    }
}

#[cfg(test)]
mod tests {
    use crate::base64url;

    use super::*;

    const HS: [JwaSigningAlgorithm; 3] = [
        JwaSigningAlgorithm::Hs256,
        JwaSigningAlgorithm::Hs384,
        JwaSigningAlgorithm::Hs512,
    ];

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn rfc7515_appendix_a1() {
        // RFC 7515 Appendix A.1: HS256 over the example signing input.
        let key = base64url::decode(
            "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
        )
        .unwrap();

        let signing_input = b"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.\
            eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

        let signature = HmacSigner::new(JwaSigningAlgorithm::Hs256, &key)
            .unwrap()
            .sign(signing_input)
            .unwrap();

        assert_eq!(
            base64url::encode(&signature),
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        );
    }

    #[test]
    fn rfc7797_section_4_1_control_without_b64() {
        // RFC 7797 §4.1: the same payload `$.02` base64url encoded (`JC4wMg`) and no `b64`, the
        // signing input of plain RFC 7515. It is the control for the §4.2 vector below.
        let key = base64url::decode(
            "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
        )
        .unwrap();

        let signature = HmacSigner::new(JwaSigningAlgorithm::Hs256, &key)
            .unwrap()
            .sign(b"eyJhbGciOiJIUzI1NiJ9.JC4wMg")
            .unwrap();

        assert_eq!(
            base64url::encode(&signature),
            "5mvfOroL-g7HyqJoozehmsaqmvTYGEq5jTI1gVvoEoQ"
        );
    }

    #[test]
    fn rfc7797_section_4_2_unencoded_payload() {
        // RFC 7797 §4.2: the key of RFC 7515 Appendix A.1, and the payload `$.02` NOT encoded.
        // The signing input is ASCII(BASE64URL(header) || '.') || payload (RFC 7797 §3).
        let key = base64url::decode(
            "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
        )
        .unwrap();

        let signing_input = b"eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19.$.02";

        let signature = HmacSigner::new(JwaSigningAlgorithm::Hs256, &key)
            .unwrap()
            .sign(signing_input)
            .unwrap();

        assert_eq!(
            base64url::encode(&signature),
            "A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY"
        );
    }

    #[test]
    fn rfc4231_section_4_7_key_larger_than_block_size() {
        // RFC 4231 test case 6: a 131-byte key, longer than every block size, so HMAC hashes
        // it first. It is the only case in the RFC with a key long enough for HS512.
        let key = [0xaa; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";

        let expected = [
            (
                JwaSigningAlgorithm::Hs256,
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            ),
            (
                JwaSigningAlgorithm::Hs384,
                "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c6\
                 0c2ef6ab4030fe8296248df163f44952",
            ),
            (
                JwaSigningAlgorithm::Hs512,
                "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352\
                 6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
            ),
        ];

        for (alg, mac) in expected {
            let signature = HmacSigner::new(alg, &key).unwrap().sign(data).unwrap();

            assert_eq!(hex(&signature), mac, "{alg:?}");
        }
    }

    #[test]
    fn signature_is_as_long_as_the_algorithm_says() {
        for alg in HS {
            let signer = HmacSigner::new(alg, &[7; 64]).unwrap();

            assert_eq!(
                Some(signer.sign(b"x").unwrap().len()),
                alg.signature_len(),
                "{alg:?}"
            );
        }
    }

    #[test]
    fn alg_is_the_one_it_was_built_with() {
        for alg in HS {
            assert_eq!(HmacSigner::new(alg, &[7; 64]).unwrap().alg(), alg);
        }
    }

    #[test]
    fn key_must_be_at_least_the_hash_output() {
        // RFC 7518 §3.2: 256, 384 and 512 bits as the minimum.
        for (alg, min) in [(HS[0], 32), (HS[1], 48), (HS[2], 64)] {
            assert_eq!(
                HmacSigner::new(alg, &vec![1; min - 1]).err(),
                Some(SignerKeyErrors::TooShort),
                "{alg:?}"
            );

            assert!(HmacSigner::new(alg, &vec![1; min]).is_ok(), "{alg:?}");
        }
    }

    #[test]
    fn a_longer_key_than_the_hash_is_valid() {
        // A 512-bit key with HS256 is allowed: the rule is a minimum, not equality.
        assert!(HmacSigner::new(JwaSigningAlgorithm::Hs256, &[1; 64]).is_ok());
    }

    #[test]
    fn empty_key_is_too_short() {
        for alg in HS {
            assert_eq!(
                HmacSigner::new(alg, &[]).err(),
                Some(SignerKeyErrors::TooShort)
            );
        }
    }

    #[test]
    fn rejects_algorithms_outside_the_family() {
        for alg in [
            JwaSigningAlgorithm::Rs256,
            JwaSigningAlgorithm::Rs384,
            JwaSigningAlgorithm::Rs512,
            JwaSigningAlgorithm::Ps256,
            JwaSigningAlgorithm::Ps384,
            JwaSigningAlgorithm::Ps512,
            JwaSigningAlgorithm::Es256,
            JwaSigningAlgorithm::Es384,
            JwaSigningAlgorithm::Es512,
            JwaSigningAlgorithm::Ed25519,
        ] {
            assert_eq!(
                HmacSigner::new(alg, &[1; 64]).err(),
                Some(SignerKeyErrors::AlgorithmMismatch),
                "{alg:?}"
            );
        }
    }

    #[test]
    fn same_key_different_algorithms_sign_differently() {
        let key = [9; 64];

        let signatures: Vec<Vec<u8>> = HS
            .iter()
            .map(|alg| HmacSigner::new(*alg, &key).unwrap().sign(b"msg").unwrap())
            .collect();

        assert_ne!(signatures[0], signatures[1]);
        assert_ne!(signatures[1], signatures[2]);
    }

    #[test]
    fn signing_does_not_change_the_signer() {
        // Each signature starts from a clone of the keyed state, so the same input gives the
        // same signature every time and one input doesn't leak into the next.
        let signer = HmacSigner::new(JwaSigningAlgorithm::Hs256, &[3; 32]).unwrap();

        let first = signer.sign(b"one").unwrap();

        signer.sign(b"two").unwrap();

        assert_eq!(signer.sign(b"one").unwrap(), first);
    }

    #[test]
    fn is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<HmacSigner>();
    }
}
