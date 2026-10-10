use serde::Serialize;

use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JwaKeyManagementAlgorithm {
    ///
    #[serde(rename = "RSA-OAEP")]
    RsaOaep,

    ///
    #[serde(rename = "RSA-OAEP-256")]
    RsaOaep256,

    ///
    #[serde(rename = "A128KW")]
    A128KW,

    ///
    #[serde(rename = "A192KW")]
    A192KW,

    ///
    #[serde(rename = "A256KW")]
    A256KW,

    ///
    #[serde(rename = "dir")]
    Dir,

    /// a
    #[serde(rename = "ECDH-ES")]
    EcdhEs,

    ///
    #[serde(rename = "ECDH-ES+A128KW")]
    EcdhEsA128Kw,

    ///
    #[serde(rename = "ECDH-ES+A192KW")]
    EcdhEsA192Kw,

    ///
    #[serde(rename = "ECDH-ES+A256KW")]
    EcdhEsA256Kw,

    ///
    #[serde(rename = "A128GCMKW")]
    A128GcmKw,

    ///
    #[serde(rename = "A192GCMKW")]
    A192GcmKw,

    ///
    #[serde(rename = "A256GCMKW")]
    A256GcmKw,

    ///
    #[serde(rename = "PBES2-HS256+A128KW")]
    Pbes2Hs256A128Kw,

    ///
    #[serde(rename = "PBES2-HS384+A192KW")]
    Pbes2Hs384A192Kw,

    ///
    #[serde(rename = "PBES2-HS512+A256KW")]
    Pbes2Hs512A256Kw,
}
