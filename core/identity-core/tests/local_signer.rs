use identity_core::{
    JwsHeader, KeyId, KeyStore, LocalSigner, sign_compact_jws_json, verify_compact_jws_json,
};
#[test]
fn encrypted_identity_preserves_signatures_and_refuses_changed_unlock_identity_or_ciphertext() {
    let id = KeyId::new("did:web:partner.example#key-1");
    let signer = LocalSigner::generate(id.clone()).unwrap();
    let public = signer.public_jwk(&id).unwrap();
    let sealed = signer.seal(&[37; 32]).unwrap();
    let restored = LocalSigner::open(id.clone(), &sealed, &[37; 32]).unwrap();
    assert_eq!(public, restored.public_jwk(&id).unwrap());
    let header: JwsHeader = serde_json::from_str(r#"{"alg":"ES256"}"#).unwrap();
    let signed = sign_compact_jws_json(
        &header,
        &serde_json::json!({"nonce":"restart"}),
        &restored,
        &id,
    )
    .unwrap();
    assert!(verify_compact_jws_json::<serde_json::Value>(&signed, &public).is_ok());
    assert!(LocalSigner::open(id.clone(), &sealed, &[38; 32]).is_err());
    assert!(LocalSigner::open(KeyId::new("other"), &sealed, &[37; 32]).is_err());
    let mut corrupt = sealed;
    corrupt[30] ^= 1;
    assert!(LocalSigner::open(id, &corrupt, &[37; 32]).is_err());
}
