use identity_core::{
    CoreResult, JwsHeader, KeyId, PartnerIdentityProofOptions, PublicJwk, Signer, b64_encode,
    sign_compact_jws_json, verify_partner_identity_proof,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
struct TestSigner(SigningKey);
impl Signer for TestSigner {
    fn sign(&self, _: &KeyId, input: &[u8]) -> CoreResult<Vec<u8>> {
        let signature: Signature = self.0.sign(input);
        Ok(signature.to_bytes().to_vec())
    }
}
fn signer(byte: u8) -> (TestSigner, PublicJwk) {
    let key = SigningKey::from_slice(&[byte; 32]).unwrap();
    let point = key.verifying_key().to_sec1_point(false);
    let public = PublicJwk::p256(
        b64_encode(point.x().unwrap()),
        b64_encode(point.y().unwrap()),
        None,
    );
    (TestSigner(key), public)
}

#[test]
fn endpoint_identity_proof_requires_fresh_exact_challenge_and_signing_key() {
    let (signer, public) = signer(3);
    let header: JwsHeader = serde_json::from_value(serde_json::json!({"alg":"ES256","typ":"partner-identity-proof+jwt","kid":"did:web:partner.example#key-1"})).unwrap();
    let payload = serde_json::json!({"iss":"did:web:partner.example","aud":"https://trust.example/challenges/one","nonce":"independent-nonce","iat":100,"exp":160});
    let jwt = sign_compact_jws_json(&header, &payload, &signer, &KeyId::new("key")).unwrap();
    let mut options = PartnerIdentityProofOptions {
        issuer: "did:web:partner.example".into(),
        key_id: "did:web:partner.example#key-1".into(),
        audience: "https://trust.example/challenges/one".into(),
        nonce: "independent-nonce".into(),
        now_unix_seconds: 120,
    };
    verify_partner_identity_proof(&jwt, &public, &options).unwrap();
    for now in [99, 160] {
        options.now_unix_seconds = now;
        assert_eq!(
            verify_partner_identity_proof(&jwt, &public, &options)
                .unwrap_err()
                .code(),
            identity_core::CoreErrorCode::TrustCheckFailed
        );
    }
    options.now_unix_seconds = 120;
    options.nonce = "another-nonce".into();
    assert_eq!(
        verify_partner_identity_proof(&jwt, &public, &options)
            .unwrap_err()
            .code(),
        identity_core::CoreErrorCode::TrustCheckFailed
    );
    options.nonce = "independent-nonce".into();
    options.audience = "https://trust.example/challenges/two".into();
    assert_eq!(
        verify_partner_identity_proof(&jwt, &public, &options)
            .unwrap_err()
            .code(),
        identity_core::CoreErrorCode::TrustCheckFailed
    );
}
