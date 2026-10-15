use crate::jwa::JwaSigningAlgorithm;

use crate::jws::signers::HmacKeyed;

use super::verifier::Verifier;

use super::verifier::VerifierErrors;

use super::verifier::VerifierKeyErrors;

/// Verifies HS256, HS384 or HS512 (RFC 7518 §3.2).
///
/// Same key rules as `HmacSigner`: at least as long as the hash output.
pub struct HmacVerifier {
    keyed: HmacKeyed,
}

impl HmacVerifier {
    pub fn new(alg: JwaSigningAlgorithm, secret: &[u8]) -> Result<Self, VerifierKeyErrors> {
        Ok(Self {
            keyed: HmacKeyed::new(alg, secret)?,
        })
    }

    /// HS256, with a key of at least 32 bytes. The dedicated form of [`new`](Self::new), for
    /// when the algorithm is written in the code and not read from configuration.
    pub fn hs256(secret: &[u8]) -> Result<Self, VerifierKeyErrors> {
        Self::new(JwaSigningAlgorithm::Hs256, secret)
    }

    /// HS384, with a key of at least 48 bytes.
    pub fn hs384(secret: &[u8]) -> Result<Self, VerifierKeyErrors> {
        Self::new(JwaSigningAlgorithm::Hs384, secret)
    }

    /// HS512, with a key of at least 64 bytes.
    pub fn hs512(secret: &[u8]) -> Result<Self, VerifierKeyErrors> {
        Self::new(JwaSigningAlgorithm::Hs512, secret)
    }
}

impl Verifier for HmacVerifier {
    fn alg(&self) -> JwaSigningAlgorithm {
        self.keyed.alg()
    }

    fn verify(&self, signing_input: &[u8], signature: &[u8]) -> Result<(), VerifierErrors> {
        if self.keyed.matches(signing_input, signature) {
            Ok(())
        } else {
            Err(VerifierErrors::InvalidSignature)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::base64url;

    use crate::jws::signers::HmacSigner;

    use crate::jws::signers::Signer;

    use super::*;

    const HS: [JwaSigningAlgorithm; 3] = [
        JwaSigningAlgorithm::Hs256,
        JwaSigningAlgorithm::Hs384,
        JwaSigningAlgorithm::Hs512,
    ];

    #[test]
    fn rfc7515_appendix_a1() {
        let key = base64url::decode(
            "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
        )
        .unwrap();

        let signing_input = b"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.\
            eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

        let signature = base64url::decode("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").unwrap();

        let verifier = HmacVerifier::new(JwaSigningAlgorithm::Hs256, &key).unwrap();

        assert_eq!(verifier.verify(signing_input, &signature), Ok(()));
    }

    #[test]
    fn signer_and_verifier_agree_for_every_algorithm() {
        let key = [7u8; 64];

        for alg in HS {
            let signature = HmacSigner::new(alg, &key).unwrap().sign(b"input").unwrap();

            let verifier = HmacVerifier::new(alg, &key).unwrap();

            assert_eq!(verifier.alg(), alg);
            assert_eq!(verifier.verify(b"input", &signature), Ok(()));
        }
    }

    #[test]
    fn any_change_is_refused() {
        let key = [7u8; 32];

        let signature = HmacSigner::new(JwaSigningAlgorithm::Hs256, &key)
            .unwrap()
            .sign(b"input")
            .unwrap();

        let verifier = HmacVerifier::new(JwaSigningAlgorithm::Hs256, &key).unwrap();

        // Another input.
        assert_eq!(
            verifier.verify(b"inpuT", &signature),
            Err(VerifierErrors::InvalidSignature)
        );

        // One bit of the signature, at each end.
        for index in [0, signature.len() - 1] {
            let mut tampered = signature.clone();

            tampered[index] ^= 1;

            assert_eq!(
                verifier.verify(b"input", &tampered),
                Err(VerifierErrors::InvalidSignature)
            );
        }

        // Truncated, extended and empty signatures.
        for tampered in [
            &signature[..signature.len() - 1],
            &[&signature[..], &[0]].concat()[..],
            &[],
        ] {
            assert_eq!(
                verifier.verify(b"input", tampered),
                Err(VerifierErrors::InvalidSignature)
            );
        }

        // Another key.
        let other = HmacVerifier::new(JwaSigningAlgorithm::Hs256, &[8u8; 32]).unwrap();

        assert_eq!(
            other.verify(b"input", &signature),
            Err(VerifierErrors::InvalidSignature)
        );
    }

    #[test]
    fn key_rules_are_the_ones_of_the_signer() {
        use crate::jws::signers::SignerKeyErrors::*;

        assert!(matches!(
            HmacVerifier::new(JwaSigningAlgorithm::Hs256, &[0; 31]),
            Err(TooShort)
        ));

        assert!(matches!(
            HmacVerifier::new(JwaSigningAlgorithm::Es256, &[0; 64]),
            Err(AlgorithmMismatch)
        ));
    }

    #[test]
    fn rejects_algorithms_outside_the_family() {
        // Everything that is not HS*, ML-DSA included, whatever the key.
        for alg in JwaSigningAlgorithm::ALL {
            if HS.contains(&alg) {
                continue;
            }

            for key in [&[1u8; 64][..], &[1u8; 4096], &[]] {
                assert!(
                    matches!(
                        HmacVerifier::new(alg, key),
                        Err(VerifierKeyErrors::AlgorithmMismatch)
                    ),
                    "{alg:?}"
                );
            }
        }
    }

    #[test]
    fn the_dedicated_constructors_are_the_generic_one_with_the_algorithm_fixed() {
        let cases: [(JwaSigningAlgorithm, fn(&[u8]) -> Result<HmacVerifier, VerifierKeyErrors>); 3] = [
            (JwaSigningAlgorithm::Hs256, HmacVerifier::hs256),
            (JwaSigningAlgorithm::Hs384, HmacVerifier::hs384),
            (JwaSigningAlgorithm::Hs512, HmacVerifier::hs512),
        ];

        for (alg, dedicated) in cases {
            let key = [3u8; 64];

            let signature = HmacSigner::new(alg, &key).unwrap().sign(b"input").unwrap();

            let verifier = dedicated(&key).unwrap();

            assert_eq!(verifier.alg(), alg);
            assert_eq!(verifier.verify(b"input", &signature), Ok(()));

            // The same key rules, and the same error.
            let too_short = vec![3u8; alg.signature_len().unwrap() - 1];

            assert!(matches!(
                dedicated(&too_short),
                Err(VerifierKeyErrors::TooShort)
            ));
            assert!(matches!(dedicated(&[]), Err(VerifierKeyErrors::TooShort)));
        }
    }

    #[test]
    fn is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<HmacVerifier>();
    }
}
