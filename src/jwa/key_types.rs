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

    /// Algorithm Key Pair (RFC 9964): keys whose algorithm fixes the parameters, e.g. ML-DSA.
    #[serde(rename = "AKP")]
    Akp,
}
