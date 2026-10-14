use crate::jwa::JwaSigningAlgorithm;

/// Something that signs the signing input of a JWS (RFC 7515 §5.1).
///
/// The algorithm is fixed by the signer and not by the caller: the builder reads `alg()` for
/// the header, so `alg` and the key can't disagree. Checking alg against the key (kty, crv,
/// size) is up to each implementation, when it is built.
pub trait Signer: Send + Sync {
    fn alg(&self) -> JwaSigningAlgorithm;

    /// Signs `signing_input` and returns the signature in the format JWS puts in the token
    /// (RFC 7518 §3.4 for ECDSA: fixed-width R || S, not DER).
    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, SignerErrors>;
}

/// Returned when building a signer: the key and the algorithm don't fit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerKeyErrors {
    /// The backend rejected the key.
    Invalid,

    /// The key is shorter than the algorithm requires (RFC 7518 §3.2 for HMAC).
    TooShort,

    /// The algorithm doesn't belong to the family of this signer, e.g. `ES256` for an HMAC one.
    AlgorithmMismatch,
}

/// Returned by [`Signer::sign`]: the signing operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerErrors {
    SigningFailed,
}
