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

impl JwaContentEncryptionAlgorithm {
    /// Returns the key len of the algorithm in bytes (8 bits -> 1 byte)
    pub fn key_len(&self) -> usize {
        match self {
            JwaContentEncryptionAlgorithm::A128GCM => 16,

            JwaContentEncryptionAlgorithm::A192GCM => 24,

            JwaContentEncryptionAlgorithm::A256GCM => 32,

            JwaContentEncryptionAlgorithm::A128CbcHs256 => 32,

            JwaContentEncryptionAlgorithm::A192CbcHs384 => 48,

            JwaContentEncryptionAlgorithm::A256CbcHs512 => 64,
        }
    }

    pub fn iv_len(&self) -> usize {
        match self {
            JwaContentEncryptionAlgorithm::A128GCM
            | JwaContentEncryptionAlgorithm::A192GCM
            | JwaContentEncryptionAlgorithm::A256GCM => 12,

            JwaContentEncryptionAlgorithm::A128CbcHs256
            | JwaContentEncryptionAlgorithm::A192CbcHs384
            | JwaContentEncryptionAlgorithm::A256CbcHs512 => 16,
        }
    }

    pub fn tag_len(&self) -> u32 {
        match self {
            JwaContentEncryptionAlgorithm::A128GCM
            | JwaContentEncryptionAlgorithm::A192GCM
            | JwaContentEncryptionAlgorithm::A256GCM
            | JwaContentEncryptionAlgorithm::A128CbcHs256 => 16,

            JwaContentEncryptionAlgorithm::A192CbcHs384 => 24,
            JwaContentEncryptionAlgorithm::A256CbcHs512 => 32,
        }
    }
}
