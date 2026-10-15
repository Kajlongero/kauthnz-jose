use super::signers::SignerErrors;

pub enum JwsVerifyErrors {}

/// Why a compact JWS was refused before any signature was checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwsParseErrors {
    // Token
    /// The token is longer than `MAX_TOKEN_LEN`.
    TokenTooLarge,

    /// Not three segments separated by `.` (RFC 7515 §7.1).
    NotCompactSerialization,

    // Header
    /// The encoded header is longer than `MAX_HEADER_LEN` allows.
    HeaderTooLarge,

    HeaderNotBase64Url,

    /// The decoded header is not valid JSON.
    HeaderNotJson,

    /// The decoded header is JSON, but not an object (RFC 7515 §4).
    HeaderNotAnObject,

    /// Header parameter names that appear more than once (RFC 7515 §4).
    DuplicateHeaderParams(Vec<String>),

    /// A header parameter with a value of the wrong JSON type.
    HeaderParamWrongType(&'static str),

    MissingAlg,

    /// `alg` is a string the library doesn't support: unknown, `none`, or deprecated.
    UnsupportedAlg,

    // Crit (and `b64`, which `crit` has to list)
    /// `crit` is an empty list (RFC 7515 §4.1.11).
    EmptyCrit,

    /// `crit` lists a name JWS already defines (RFC 7515 §4.1.11).
    CritRegisteredParam(String),

    /// `crit` lists an extension the library doesn't implement.
    CritUnsupported(String),

    /// `crit` lists a name that is not a member of the header (RFC 7515 §4.1.11).
    CritMissingParam(String),

    /// `b64: false` without `b64` in `crit` (RFC 7797 §6).
    B64WithoutCrit,

    // Payload and signature
    /// `b64: false` with the payload inside the token. Only detached is supported: an
    /// unencoded payload could hold `.` or characters outside the compact charset
    /// (RFC 7797 §5.2).
    UnencodedAttachedPayload,

    PayloadNotBase64Url,

    /// The signature is empty or not the length `alg` produces.
    SignatureLength,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwsSigningErrors {
    /// The serialized protected header is longer than `MAX_HEADER_LEN`.
    HeaderTooLarge,

    /// The protected header could not be serialized (not expected with the current fields).
    HeaderSerialization,

    /// A custom header parameter with an empty name.
    EmptyHeaderParamName,

    /// The signer failed while signing. Building the signer is a separate step, so key
    /// errors never reach here.
    Signer(SignerErrors),

    /// A custom header parameter whose name is registered or controlled by the library
    /// (`alg`, `crit`, `b64`, or one that has its own builder method).
    ReservedHeaderParam(String),

    /// The same custom header parameter name more than once. Names must be unique
    /// (RFC 7515 §4).
    DuplicateHeaderParam(String),

    /// A custom header parameter name with a control character (Unicode category Cc: U+0000
    /// to U+001F and U+007F to U+009F). It is valid JSON once escaped, but it is a risk for
    /// whatever reads the header later (C strings, logs).
    ControlCharInHeaderParamName(String),
}
