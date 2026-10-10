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
}

impl JwaSigningAlgorithm {
    pub fn kty(&self) -> JwaKty {
        match self {
            Self::Ed25519 => JwaKty::Okp,

            Self::Es256 | Self::Es384 | Self::Es512 => JwaKty::Ec,

            Self::Hs256 | Self::Hs384 | Self::Hs512 => JwaKty::Oct,

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
            | Self::Ps512 => None,

            Self::Es256 => Some(JwaCurve::P256),

            Self::Es384 => Some(JwaCurve::P384),

            Self::Es512 => Some(JwaCurve::P521),

            Self::Ed25519 => Some(JwaCurve::Ed25519),
        }
    }
}
