/// Header parameter names registered for JWS (RFC 7515 §4.1.1 to §4.1.11).
///
/// These are the names `crit` can't list (RFC 7515 §4.1.11). `b64` is not here: it is defined
/// by an extension (RFC 7797) and it has to appear in `crit`.
pub(super) const JWS_REGISTERED_HEADER_PARAMS: [&str; 11] = [
    "alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit",
];

/// Names a custom header parameter can't use: the ones the builder sets itself, plus every
/// name registered for JWS, `b64` (RFC 7797 §3) and those that JWE and JWA define
/// (RFC 7516 §4.1, RFC 7518 §4.6.1, §4.7.1, §4.8.1), which mean nothing in a JWS and could be
/// misread by a receiver.
pub(super) const RESERVED_HEADER_PARAMS: [&str; 21] = [
    "alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit", "b64",
    "enc", "zip", "epk", "apu", "apv", "iv", "tag", "p2s", "p2c",
];

/// Largest protected header, serialized, the library will write (and, in the same way, read).
/// A bound on what an attacker-controlled or buggy caller can make the signer allocate.
pub(super) const MAX_HEADER_LEN: usize = 8 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_contains_every_registered_name() {
        for name in JWS_REGISTERED_HEADER_PARAMS {
            assert!(RESERVED_HEADER_PARAMS.contains(&name), "{name}");
        }
    }

    #[test]
    fn crit_may_list_b64() {
        // RFC 7797 §6: `b64` has to be listed in `crit`, so it can't be in the forbidden set.
        assert!(!JWS_REGISTERED_HEADER_PARAMS.contains(&"b64"));
        assert!(RESERVED_HEADER_PARAMS.contains(&"b64"));
    }

    #[test]
    fn no_duplicates() {
        for list in [&JWS_REGISTERED_HEADER_PARAMS[..], &RESERVED_HEADER_PARAMS[..]] {
            let unique: std::collections::HashSet<_> = list.iter().collect();

            assert_eq!(unique.len(), list.len());
        }
    }
}
