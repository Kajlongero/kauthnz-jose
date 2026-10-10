use serde::Serialize;

use serde::Deserialize;

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
