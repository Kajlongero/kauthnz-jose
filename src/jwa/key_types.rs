use serde::Serialize;

use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JwaKty {
    ///
    #[serde(rename = "RSA")]
    Rsa,

    ///
    #[serde(rename = "EC")]
    Ec,

    ///
    #[serde(rename = "oct")]
    Oct,

    ///
    #[serde(rename = "OKP")]
    Okp,
}
