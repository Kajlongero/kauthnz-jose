use super::signers::SignerErrors;

pub enum JwsVerifyErrors {}

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
