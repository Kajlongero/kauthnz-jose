use crate::jwa::JwaSigningAlgorithm;

use crate::jws::signers::SignerKeyErrors;

/// Returned when building a verifier: the key and the algorithm don't fit. The same cases as
/// for a signer.
pub type VerifierKeyErrors = SignerKeyErrors;

/// Something that checks the signature of a JWS (RFC 7515 §5.2).
///
/// The mirror of [`Signer`](crate::jws::signers::Signer): the algorithm is fixed by the
/// verifier and never taken from the token, so a token can't pick how it is checked. Checking
/// alg against the key is up to each implementation, when it is built.
pub trait Verifier: Send + Sync {
    fn alg(&self) -> JwaSigningAlgorithm;

    /// Checks `signature` (already decoded, in the format JWS carries: fixed-width R || S for
    /// ECDSA, not DER) over `signing_input`. The error says nothing about why it failed.
    fn verify(&self, signing_input: &[u8], signature: &[u8]) -> Result<(), VerifierErrors>;
}

/// Returned by [`Verifier::verify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierErrors {
    /// The signature is not valid for this input and key. Deliberately a single case.
    InvalidSignature,
}
