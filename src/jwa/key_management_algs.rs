use serde::Serialize;

use serde::Deserialize;

use super::curves::JwaCurve;

use super::key_types::JwaKty;

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
    A128Kw,

    ///
    #[serde(rename = "A192KW")]
    A192Kw,

    ///
    #[serde(rename = "A256KW")]
    A256Kw,

    ///
    #[serde(rename = "dir")]
    Dir,

    ///
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

impl JwaKeyManagementAlgorithm {
    pub const fn kty(&self) -> &'static [JwaKty] {
        match self {
            Self::RsaOaep | Self::RsaOaep256 => &[JwaKty::Rsa],

            Self::EcdhEs | Self::EcdhEsA128Kw | Self::EcdhEsA192Kw | Self::EcdhEsA256Kw => {
                &[JwaKty::Ec, JwaKty::Okp]
            }

            Self::Dir
            | Self::A128Kw
            | Self::A192Kw
            | Self::A256Kw
            | Self::A128GcmKw
            | Self::A192GcmKw
            | Self::A256GcmKw
            | Self::Pbes2Hs256A128Kw
            | Self::Pbes2Hs384A192Kw
            | Self::Pbes2Hs512A256Kw => &[JwaKty::Oct],
        }
    }

    pub const fn crv(&self) -> &'static [JwaCurve] {
        match self {
            Self::EcdhEs | Self::EcdhEsA128Kw | Self::EcdhEsA192Kw | Self::EcdhEsA256Kw => &[
                JwaCurve::P256,
                JwaCurve::P384,
                JwaCurve::P521,
                JwaCurve::X25519,
            ],

            Self::Dir
            | Self::RsaOaep
            | Self::RsaOaep256
            | Self::A128Kw
            | Self::A192Kw
            | Self::A256Kw
            | Self::A128GcmKw
            | Self::A192GcmKw
            | Self::A256GcmKw
            | Self::Pbes2Hs256A128Kw
            | Self::Pbes2Hs384A192Kw
            | Self::Pbes2Hs512A256Kw => &[],
        }
    }

    pub fn accepts_kty(&self, kty: JwaKty) -> bool {
        self.kty().contains(&kty)
    }

    pub fn accepts_crv(&self, crv: JwaCurve) -> bool {
        self.crv().contains(&crv)
    }
}
