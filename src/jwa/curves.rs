use serde::Serialize;

use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JwaCurve {
    ///
    #[serde(rename = "P-256")]
    P256,

    ///
    #[serde(rename = "P-384")]
    P384,

    ///
    #[serde(rename = "P-521")]
    P521,

    ///
    #[serde(rename = "Ed25519")]
    Ed25519,

    ///  
    #[serde(rename = "X25519")]
    X25519,
}
