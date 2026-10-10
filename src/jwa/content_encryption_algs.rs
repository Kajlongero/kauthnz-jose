use serde::Serialize;

use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JwaContentEncryptionAlgorithm {
    ///
    #[serde(rename = "A128GCM")]
    A128GCM,

    ///
    #[serde(rename = "A192GCM")]
    A192GCM,

    ///
    #[serde(rename = "A256GCM")]
    A256GCM,

    ///
    #[serde(rename = "A128CBC-HS256")]
    A128CbcHs256,

    ///
    #[serde(rename = "A192CBC-HS384")]
    A192CbcHs384,

    ///
    #[serde(rename = "A256CBC-HS512")]
    A256CbcHs512,
}
