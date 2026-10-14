use serde::Serialize;

use serde::Deserialize;

use super::curves::JwaCurve;

use super::key_types::JwaKty;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JwaSigningAlgorithm {
    ///
    #[serde(rename = "HS256")]
    Hs256,

    ///
    #[serde(rename = "HS384")]
    Hs384,

    ///
    #[serde(rename = "HS512")]
    Hs512,

    ///
    #[serde(rename = "RS256")]
    Rs256,

    ///
    #[serde(rename = "RS384")]
    Rs384,

    ///
    #[serde(rename = "RS512")]
    Rs512,

    ///
    #[serde(rename = "PS256")]
    Ps256,

    ///
    #[serde(rename = "PS384")]
    Ps384,

    ///
    #[serde(rename = "PS512")]
    Ps512,

    ///
    #[serde(rename = "ES256")]
    Es256,

    ///
    #[serde(rename = "ES384")]
    Es384,

    ///
    #[serde(rename = "ES512")]
    Es512,

    ///
    #[serde(rename = "Ed25519")]
    Ed25519,

    /// ML-DSA-44 (RFC 9964), FIPS 204 parameter set 2.
    #[serde(rename = "ML-DSA-44")]
    MlDsa44,

    /// ML-DSA-65 (RFC 9964), FIPS 204 parameter set 3.
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,

    /// ML-DSA-87 (RFC 9964), FIPS 204 parameter set 5.
    #[serde(rename = "ML-DSA-87")]
    MlDsa87,
}

impl JwaSigningAlgorithm {
    pub fn kty(&self) -> JwaKty {
        match self {
            Self::Ed25519 => JwaKty::Okp,

            Self::Es256 | Self::Es384 | Self::Es512 => JwaKty::Ec,

            Self::Hs256 | Self::Hs384 | Self::Hs512 => JwaKty::Oct,

            Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 => JwaKty::Akp,

            Self::Rs256 | Self::Rs384 | Self::Rs512 | Self::Ps256 | Self::Ps384 | Self::Ps512 => {
                JwaKty::Rsa
            }
        }
    }

    pub fn crv(&self) -> Option<JwaCurve> {
        match self {
            Self::Hs256
            | Self::Hs384
            | Self::Hs512
            | Self::Rs256
            | Self::Rs384
            | Self::Rs512
            | Self::Ps256
            | Self::Ps384
            | Self::Ps512
            | Self::MlDsa44
            | Self::MlDsa65
            | Self::MlDsa87 => None,

            Self::Es256 => Some(JwaCurve::P256),

            Self::Es384 => Some(JwaCurve::P384),

            Self::Es512 => Some(JwaCurve::P521),

            Self::Ed25519 => Some(JwaCurve::Ed25519),
        }
    }

    /// Length in bytes of the signature the algorithm produces, when the algorithm itself fixes it.
    ///
    /// RS* and PS* return `None`: the signature is as long as the RSA key's modulus
    /// (RFC 7518 §3.3 and §3.5), so it can't be known without the key.
    pub const fn signature_len(&self) -> Option<usize> {
        match self {
            // Size of the hash output (RFC 7518 §3.2).
            Self::Hs256 => Some(32),

            Self::Hs384 => Some(48),

            Self::Hs512 => Some(64),

            // R || S, fixed width, twice the size of the curve order (RFC 7518 §3.4).
            Self::Es256 => Some(64),

            Self::Es384 => Some(96),

            Self::Es512 => Some(132),

            // RFC 8032 §5.1.6: R (32) || S (32).
            Self::Ed25519 => Some(64),

            // FIPS 204 Table 2: signature sizes of each parameter set (RFC 9964).
            Self::MlDsa44 => Some(2420),

            Self::MlDsa65 => Some(3309),

            Self::MlDsa87 => Some(4627),

            Self::Rs256 | Self::Rs384 | Self::Rs512 | Self::Ps256 | Self::Ps384 | Self::Ps512 => {
                None
            }
        }
    }

    /// Length in bytes of the single public value of the JWK (`x` for OKP, `pub` for AKP), when
    /// the algorithm itself fixes it.
    pub const fn public_key_len(&self) -> Option<usize> {
        match self {
            // RFC 8032 §5.1.5, carried in `x` (RFC 8037 §2).
            Self::Ed25519 => Some(32),

            // FIPS 204 Table 2, carried in `pub` (RFC 9964).
            Self::MlDsa44 => Some(1312),

            Self::MlDsa65 => Some(1952),

            Self::MlDsa87 => Some(2592),

            // Not a single fixed value, so it is left out on purpose:
            // - ES*: the JWK has two coordinates, `x` and `y`, and their size depends on the
            //   curve, not on the algorithm (RFC 7518 §6.2.1.2).
            // - RS* and PS*: it depends on the RSA modulus (RFC 7518 §3.3 only sets a minimum).
            // - HS*: there is no public key.
            _ => None,
        }
    }
}
