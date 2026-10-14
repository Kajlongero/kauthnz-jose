/// How the payload enters the signing input.
///
/// `Base64Url` is the default and is never written in the header. `Unencoded` is `b64: false`
/// (RFC 7797 §3) and is always written together with `crit: ["b64"]` (RFC 7797 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::jws) enum PayloadEncoding {
    Base64Url,

    Unencoded,
}
