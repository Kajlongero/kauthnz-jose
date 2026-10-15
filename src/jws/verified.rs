use std::borrow::Cow;

use serde_json::Map;

use serde_json::Value;

use crate::base64url;

use crate::jwa::JwaSigningAlgorithm;

use super::errors::JwsVerifyErrors;

use super::header::ContentType;

use super::header::PayloadEncoding;

use super::header::TokenType;

use super::header::media_type_matches;

use super::validator::JwsValidator;

use super::validator::UnverifiedHeader;

use super::validator::UnverifiedPayload;

use super::verifiers::Verifier;

/// A JWS whose signature was checked. It can only come out of [`JwsValidator::verify`] or
/// [`JwsValidator::verify_detached`].
pub struct VerifiedJws {
    header: VerifiedHeader,

    /// The payload that was inside the token, decoded. `None` when it was detached: the caller
    /// already has it, and it is the one that was checked.
    payload: Option<Vec<u8>>,
}

impl JwsValidator<'_> {
    /// Verifies a compact JWS whose payload is inside the token.
    ///
    /// The rules (`typ`, `cty`) are applied first, before any cryptography, and what was read
    /// from the token is used as it is. If the signature holds, that is handed over, moved and
    /// not copied, to the verified types.
    pub fn verify<V>(self, verifier: &V) -> Result<VerifiedJws, JwsVerifyErrors>
    where
        V: Verifier + ?Sized,
    {
        self.run(verifier, None)
    }

    /// Verifies a compact JWS whose payload is detached (`header..signature`), with `payload`:
    /// exactly the bytes that were signed. A token that carries its own payload is refused,
    /// and nothing is guessed.
    pub fn verify_detached<V>(
        self,
        verifier: &V,
        payload: &[u8],
    ) -> Result<VerifiedJws, JwsVerifyErrors>
    where
        V: Verifier + ?Sized,
    {
        self.run(verifier, Some(payload))
    }

    fn run<V>(self, verifier: &V, detached: Option<&[u8]>) -> Result<VerifiedJws, JwsVerifyErrors>
    where
        V: Verifier + ?Sized,
    {
        {
            let header = self.decode_header().map_err(JwsVerifyErrors::Parse)?;

            // The rules, in order, and none of them needs the key.
            if header.alg() != verifier.alg() {
                return Err(JwsVerifyErrors::AlgorithmMismatch);
            }

            check_expected(
                header.typ(),
                self.expected_typ,
                JwsVerifyErrors::TypMismatch,
            )?;

            check_expected(
                header.cty(),
                self.expected_cty,
                JwsVerifyErrors::CtyMismatch,
            )?;

            let encoding = header.encoding();

            let payload = self.decode_payload().map_err(JwsVerifyErrors::Parse)?;

            let signature = self.decode_signature().map_err(JwsVerifyErrors::Parse)?;

            let signing_input: Cow<[u8]> = match (payload, detached) {
                // `header.payload`, as it came.
                (UnverifiedPayload::Attached(_), None) => {
                    Cow::Borrowed(self.signing_prefix().as_bytes())
                }

                (UnverifiedPayload::Attached(_), Some(_)) => {
                    return Err(JwsVerifyErrors::UnexpectedPayload);
                }

                (UnverifiedPayload::Detached, None) => {
                    return Err(JwsVerifyErrors::MissingPayload);
                }

                // `header.` followed by the payload the way `b64` says (RFC 7797 §3).
                (UnverifiedPayload::Detached, Some(bytes)) => {
                    let mut input = self.signing_prefix().as_bytes().to_vec();

                    match encoding {
                        PayloadEncoding::Base64Url => {
                            input.extend_from_slice(base64url::encode(bytes).as_bytes());
                        }

                        PayloadEncoding::Unencoded => input.extend_from_slice(bytes),
                    }

                    Cow::Owned(input)
                }
            };

            verifier
                .verify(&signing_input, signature)
                .map_err(|_| JwsVerifyErrors::InvalidSignature)?;
        }

        // The swap: what was read is handed over, as it is, to the verified types.
        let (header, payload) = self.into_decoded().map_err(JwsVerifyErrors::Parse)?;

        Ok(VerifiedJws {
            header: VerifiedHeader(header),
            payload: payload.into_attached(),
        })
    }
}

impl VerifiedJws {
    pub fn header(&self) -> &VerifiedHeader {
        &self.header
    }

    /// The attached payload, decoded. `None` when it was detached.
    pub fn payload(&self) -> Option<&[u8]> {
        self.payload.as_deref()
    }

    /// Requires the `typ` to be `T::TYP`, now that it is authenticated. It is the same check as
    /// the one `JwsValidator::typ` makes before the signature, and it doesn't replace it: that
    /// one saves work, this one is made on data that can be trusted.
    pub fn typ<T: TokenType>(self) -> Result<Self, JwsVerifyErrors> {
        check_expected(
            self.header.typ(),
            Some(T::TYP),
            JwsVerifyErrors::TypMismatch,
        )?;

        Ok(self)
    }

    /// Requires the `cty` to be `C::CTY`, now that it is authenticated.
    pub fn cty<C: ContentType>(self) -> Result<Self, JwsVerifyErrors> {
        check_expected(
            self.header.cty(),
            Some(C::CTY),
            JwsVerifyErrors::CtyMismatch,
        )?;

        Ok(self)
    }
}

/// The protected header of a verified JWS: the same fields as the unverified one, but now it
/// is what the signer wrote, and the type says so.
pub struct VerifiedHeader(UnverifiedHeader);

impl VerifiedHeader {
    pub fn alg(&self) -> JwaSigningAlgorithm {
        self.0.alg()
    }

    pub fn typ(&self) -> Option<&str> {
        self.0.typ()
    }

    pub fn cty(&self) -> Option<&str> {
        self.0.cty()
    }

    pub fn kid(&self) -> Option<&str> {
        self.0.kid()
    }

    /// Every member other than `alg`, `typ`, `cty`, `kid`, `crit` and `b64`.
    pub fn extra(&self) -> &Map<String, Value> {
        self.0.extra()
    }
}

/// `Ok` when nothing is expected, or when what the token carries is what is expected.
fn check_expected(
    actual: Option<&str>,
    expected: Option<&str>,
    error: JwsVerifyErrors,
) -> Result<(), JwsVerifyErrors> {
    match (expected, actual) {
        (None, _) => Ok(()),

        (Some(expected), Some(actual)) if media_type_matches(actual, expected) => Ok(()),

        (Some(_), _) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::jws::errors::JwsParseErrors;

    use crate::jws::signers::HmacSigner;

    use crate::jws::signers::Signer;

    use crate::jws::verifiers::HmacVerifier;

    const KEY_B64: &str =
        "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";

    // RFC 7515 Appendix A.1.
    const A1: &str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.\
        eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.\
        dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    // RFC 7797 §4.1: the control, `$.02` base64url encoded, no `b64`.
    const RFC7797_CONTROL: &str =
        "eyJhbGciOiJIUzI1NiJ9.JC4wMg.5mvfOroL-g7HyqJoozehmsaqmvTYGEq5jTI1gVvoEoQ";

    // RFC 7797 §4.2: unencoded and detached.
    const RFC7797_DETACHED: &str = "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..\
        A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY";

    struct AccessToken;

    impl TokenType for AccessToken {
        const TYP: &'static str = "at+jwt";
    }

    struct Jwt;

    impl TokenType for Jwt {
        const TYP: &'static str = "JWT";
    }

    struct NestedJwt;

    impl ContentType for NestedJwt {
        const CTY: &'static str = "JWT";
    }

    fn rfc_verifier() -> HmacVerifier {
        let key = base64url::decode(KEY_B64).unwrap();

        HmacVerifier::new(JwaSigningAlgorithm::Hs256, &key).unwrap()
    }

    fn test_verifier() -> HmacVerifier {
        HmacVerifier::new(JwaSigningAlgorithm::Hs256, &[9; 32]).unwrap()
    }

    /// The token, read, and ready to be verified.
    fn jws(token: &str) -> JwsValidator<'_> {
        JwsValidator::new(token).expect("the token should split")
    }

    fn verify(token: &str, verifier: &HmacVerifier) -> Result<VerifiedJws, JwsVerifyErrors> {
        jws(token).verify(verifier)
    }

    fn err(result: Result<VerifiedJws, JwsVerifyErrors>) -> JwsVerifyErrors {
        result.err().expect("should be refused")
    }

    /// A token signed with the test key: `header` is the JSON of the header, `payload` is put
    /// inside as it is, already encoded, and the signature is real.
    fn signed(header: &str, payload: &str) -> String {
        let header = base64url::encode(header.as_bytes());

        let signing_input = format!("{header}.{payload}");

        let signature = HmacSigner::new(JwaSigningAlgorithm::Hs256, &[9; 32])
            .unwrap()
            .sign(signing_input.as_bytes())
            .unwrap();

        format!("{signing_input}.{}", base64url::encode(&signature))
    }

    #[test]
    fn rfc7515_appendix_a1() {
        let jws = verify(A1, &rfc_verifier()).unwrap();

        assert_eq!(jws.header().alg(), JwaSigningAlgorithm::Hs256);
        assert_eq!(jws.header().typ(), Some("JWT"));
        assert!(jws.payload().unwrap().starts_with(b"{\"iss\":\"joe\""));
    }

    #[test]
    fn rfc7797_section_4_1_control() {
        let jws = verify(RFC7797_CONTROL, &rfc_verifier()).unwrap();

        assert_eq!(jws.payload(), Some(&b"$.02"[..]));
    }

    #[test]
    fn rfc7797_section_4_2_detached_and_unencoded() {
        let jws = jws(RFC7797_DETACHED)
            .verify_detached(&rfc_verifier(), b"$.02")
            .unwrap();

        assert_eq!(jws.header().alg(), JwaSigningAlgorithm::Hs256);

        // Detached: the payload is the caller's, nothing comes back.
        assert_eq!(jws.payload(), None);
    }

    #[test]
    fn detached_payload_is_what_was_signed() {
        let verifier = rfc_verifier();

        for payload in [&b"$.03"[..], b"$.02 ", b"", b"$.0"] {
            assert_eq!(
                err(jws(RFC7797_DETACHED).verify_detached(&verifier, payload)),
                JwsVerifyErrors::InvalidSignature,
                "{payload:?}"
            );
        }
    }

    #[test]
    fn an_attached_token_can_be_made_detached_with_base64url() {
        // RFC 7515 Appendix F: take the payload out of A.1 and bring it separately. The
        // signing input is the same, so the signature still holds.
        let (header, rest) = A1.split_once('.').unwrap();
        let (payload, signature) = rest.split_once('.').unwrap();

        let detached = format!("{header}..{signature}");

        let payload = base64url::decode(payload).unwrap();

        let verifier = rfc_verifier();

        let jws = jws(&detached).verify_detached(&verifier, &payload).unwrap();

        assert_eq!(jws.payload(), None);

        // And not with any other bytes.
        let mut other = payload.clone();

        other[0] ^= 1;

        assert_eq!(
            err(self::jws(&detached).verify_detached(&verifier, &other)),
            JwsVerifyErrors::InvalidSignature
        );
    }

    #[test]
    fn payload_has_to_match_what_the_token_carries() {
        let verifier = rfc_verifier();

        assert_eq!(
            err(jws(A1).verify_detached(&verifier, b"x")),
            JwsVerifyErrors::UnexpectedPayload
        );
        assert_eq!(
            err(jws(RFC7797_DETACHED).verify(&verifier)),
            JwsVerifyErrors::MissingPayload
        );

        // An empty payload is a payload, and `verify` (no payload) is not.
        assert_eq!(
            err(jws(A1).verify_detached(&verifier, b"")),
            JwsVerifyErrors::UnexpectedPayload
        );
        assert_eq!(
            err(jws(RFC7797_DETACHED).verify_detached(&verifier, b"")),
            JwsVerifyErrors::InvalidSignature
        );
    }

    #[test]
    fn the_token_does_not_pick_the_algorithm() {
        // A valid HS256 token against an HS384 verifier.
        let verifier = HmacVerifier::new(JwaSigningAlgorithm::Hs384, &[1; 48]).unwrap();

        assert_eq!(
            err(verify(A1, &verifier)),
            JwsVerifyErrors::AlgorithmMismatch
        );
    }

    #[test]
    fn another_key_is_refused() {
        let verifier = HmacVerifier::new(JwaSigningAlgorithm::Hs256, &[1; 32]).unwrap();

        assert_eq!(
            err(verify(A1, &verifier)),
            JwsVerifyErrors::InvalidSignature
        );
    }

    #[test]
    fn tampering_with_any_segment_is_refused() {
        let (header, rest) = A1.split_once('.').unwrap();
        let (payload, signature) = rest.split_once('.').unwrap();

        // A different payload, a different signature and a different header.
        let other_payload = payload.replacen("eyJp", "eyJq", 1);
        let other_signature = signature.replacen("dBjf", "dBjg", 1);
        let other_header = header.replacen("eyJ0", "eyJ1", 1);

        assert_ne!(other_payload, payload);
        assert_ne!(other_signature, signature);
        assert_ne!(other_header, header);

        let verifier = rfc_verifier();

        for token in [
            format!("{header}.{other_payload}.{signature}"),
            format!("{header}.{payload}.{other_signature}"),
            format!("{other_header}.{payload}.{signature}"),
        ] {
            assert!(
                verify(&token, &verifier).is_err(),
                "a modified token was accepted: {token}"
            );
        }
    }

    #[test]
    fn a_signature_that_is_not_canonical_base64url_is_a_read_error() {
        let (rest, signature) = A1.rsplit_once('.').unwrap();

        let verifier = rfc_verifier();

        for bad in [
            signature.replacen('-', "+", 1),
            // The last char carries 4 unused bits, and they have to be zero.
            format!("{}l", &signature[..signature.len() - 1]),
        ] {
            assert_eq!(
                err(verify(&format!("{rest}.{bad}"), &verifier)),
                JwsVerifyErrors::Parse(JwsParseErrors::SignatureNotBase64Url),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_signed_payload_that_is_not_canonical_base64url_is_a_read_error() {
        // The signature is valid over what is in the token, but `Zh` has unused bits set.
        let token = signed(r#"{"alg":"HS256"}"#, "Zh");

        assert_eq!(
            err(verify(&token, &test_verifier())),
            JwsVerifyErrors::Parse(JwsParseErrors::PayloadNotBase64Url)
        );
    }

    #[test]
    fn round_trip_through_the_signer_for_every_algorithm() {
        for (alg, name) in [
            (JwaSigningAlgorithm::Hs256, "HS256"),
            (JwaSigningAlgorithm::Hs384, "HS384"),
            (JwaSigningAlgorithm::Hs512, "HS512"),
        ] {
            let key = [9u8; 64];

            let header = base64url::encode(format!(r#"{{"alg":"{name}"}}"#).as_bytes());

            let signing_input = format!("{header}.{}", base64url::encode(b"hello"));

            let signature = HmacSigner::new(alg, &key)
                .unwrap()
                .sign(signing_input.as_bytes())
                .unwrap();

            let token = format!("{signing_input}.{}", base64url::encode(&signature));

            let verifier = HmacVerifier::new(alg, &key).unwrap();

            let jws = verify(&token, &verifier).unwrap();

            assert_eq!(jws.payload(), Some(&b"hello"[..]));
            assert_eq!(jws.header().alg(), alg);
        }
    }

    #[test]
    fn verify_accepts_a_trait_object() {
        let boxed: Box<dyn Verifier> = Box::new(rfc_verifier());

        assert!(jws(A1).verify(boxed.as_ref()).is_ok());
    }

    #[test]
    fn a_token_that_was_read_first_is_verified_as_it_is() {
        // Read the header to pick the key, apply a rule of our own, then verify the same
        // object. That nothing is decoded twice is what `JwsValidator` tests (the caches).
        let unverified = JwsValidator::new(A1).unwrap();

        assert_eq!(unverified.decode_header().unwrap().typ(), Some("JWT"));
        assert!(unverified.decode_payload().unwrap().attached().is_some());

        let verified = unverified.verify(&rfc_verifier()).unwrap();

        assert_eq!(verified.header().typ(), Some("JWT"));
        assert!(verified.payload().unwrap().starts_with(b"{\"iss\":\"joe\""));
    }

    #[test]
    fn typ_is_checked_before_the_signature_and_after_it() {
        let verifier = test_verifier();

        let token = signed(r#"{"alg":"HS256","typ":"at+jwt"}"#, "cGF5");

        // The expected one, with the prefix and in another case, passes both.
        for typ in ["at+jwt", "application/at+jwt", "AT+JWT"] {
            let token = signed(&format!(r#"{{"alg":"HS256","typ":"{typ}"}}"#), "cGF5");

            let jws = jws(&token).typ::<AccessToken>().verify(&verifier).unwrap();

            assert!(jws.typ::<AccessToken>().is_ok(), "{typ}");
        }

        // Another type is refused, and it is refused by the cheap check: a token with the
        // wrong `typ` and a bad signature says `TypMismatch`, not `InvalidSignature`.
        let (rest, _) = token.rsplit_once('.').unwrap();

        let forged = format!("{rest}.{}", base64url::encode(&[0; 32]));

        assert_eq!(
            err(jws(&forged).typ::<Jwt>().verify(&verifier)),
            JwsVerifyErrors::TypMismatch
        );

        // And the post check, on the authenticated token, says the same.
        let verified = verify(&token, &verifier).unwrap();

        assert_eq!(
            verified.typ::<Jwt>().err(),
            Some(JwsVerifyErrors::TypMismatch)
        );
    }

    #[test]
    fn a_missing_typ_is_refused_when_one_is_expected() {
        let verifier = test_verifier();

        let token = signed(r#"{"alg":"HS256"}"#, "cGF5");

        assert_eq!(
            err(jws(&token).typ::<AccessToken>().verify(&verifier)),
            JwsVerifyErrors::TypMismatch
        );

        // Nothing expected, nothing checked.
        let verified = verify(&token, &verifier).unwrap();

        assert_eq!(verified.header().typ(), None);
        assert_eq!(
            verified.typ::<AccessToken>().err(),
            Some(JwsVerifyErrors::TypMismatch)
        );
    }

    #[test]
    fn cty_works_like_typ() {
        let verifier = test_verifier();

        let nested = signed(r#"{"alg":"HS256","cty":"JWT"}"#, "cGF5");
        let other = signed(r#"{"alg":"HS256","cty":"text/plain"}"#, "cGF5");
        let none = signed(r#"{"alg":"HS256"}"#, "cGF5");

        assert!(
            jws(&nested)
                .cty::<NestedJwt>()
                .verify(&verifier)
                .unwrap()
                .cty::<NestedJwt>()
                .is_ok()
        );

        for token in [&other, &none] {
            assert_eq!(
                err(jws(token).cty::<NestedJwt>().verify(&verifier)),
                JwsVerifyErrors::CtyMismatch
            );
        }

        assert_eq!(
            verify(&other, &verifier).unwrap().cty::<NestedJwt>().err(),
            Some(JwsVerifyErrors::CtyMismatch)
        );
    }

    #[test]
    fn the_checks_chain_after_verify() {
        let verifier = test_verifier();

        let token = signed(r#"{"alg":"HS256","typ":"at+jwt","cty":"JWT"}"#, "cGF5");

        let verified = jws(&token)
            .typ::<AccessToken>()
            .cty::<NestedJwt>()
            .verify(&verifier)
            .unwrap()
            .typ::<AccessToken>()
            .unwrap()
            .cty::<NestedJwt>()
            .unwrap();

        assert_eq!(verified.payload(), Some(&b"pay"[..]));
    }

    #[test]
    fn errors_from_reading_come_out_wrapped() {
        // A header that is not even base64url, found when `verify` reads it.
        assert_eq!(
            err(jws("!!!.cGF5.c2ln").verify(&rfc_verifier())),
            JwsVerifyErrors::Parse(JwsParseErrors::HeaderNotBase64Url)
        );
    }
}
