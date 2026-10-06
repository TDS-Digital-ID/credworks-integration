use identity_core::{
    ScalarCredentialDefinition, SubjectValidationMode, validate_scalar_definition,
    validate_scalar_subject,
};
use serde_json::json;
fn definition() -> ScalarCredentialDefinition {
    serde_json::from_value(json!({
        "id":"urn:example:membership","version":"1","credential_type":"ExampleMembershipCredential",
        "label":"Membership","max_validity_seconds":3600,
        "claims":[{"name":"member","label":"Member","value_type":"boolean","required":true}],
        "profiles":[{"name":"access","claim_paths":[["credentialSubject","member"]]}]
    }))
    .unwrap()
}
#[test]
fn neutral_scalar_definition_validates_complete_and_disclosed_values_without_coercion() {
    let definition = definition();
    validate_scalar_definition(&definition).unwrap();
    validate_scalar_subject(
        &definition,
        &json!({"member":true}),
        SubjectValidationMode::Complete,
    )
    .unwrap();
    assert!(
        validate_scalar_subject(
            &definition,
            &json!({"member":"true"}),
            SubjectValidationMode::Complete
        )
        .is_err()
    );
    assert!(
        validate_scalar_subject(&definition, &json!({}), SubjectValidationMode::Complete).is_err()
    );
    validate_scalar_subject(&definition, &json!({}), SubjectValidationMode::Disclosed).unwrap();
}

use identity_core::{
    CoreErrorCode, CoreResult, IssuerAuthorization, IssuerAuthorizationRequest,
    IssuerAuthorizations, JwsHeader, KeyId, PublicJwk, Signer, b64_encode,
    public_jwk_sha256_thumbprint, sign_issuer_authorizations, verify_issuer_authorization,
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
    let jwk = PublicJwk::p256(
        b64_encode(point.x().unwrap()),
        b64_encode(point.y().unwrap()),
        None,
    );
    (TestSigner(key), jwk)
}
fn authority() -> (IssuerAuthorizations, IssuerAuthorizationRequest) {
    let (_, issuer_key) = signer(2);
    let grant = IssuerAuthorization {
        credential_issuer_did: "did:web:issuer.example".into(),
        credential_issuer_key_id: "did:web:issuer.example#key-1".into(),
        credential_issuer_public_jwk_sha256_thumbprint: public_jwk_sha256_thumbprint(&issuer_key)
            .unwrap(),
        definition: definition(),
        status: identity_core::TrustListStatus::Active,
        key_state: None,
        status_authority: None,
    };
    let request = IssuerAuthorizationRequest {
        registry_did: "did:web:trust.example".into(),
        credential_issuer_did: grant.credential_issuer_did.clone(),
        credential_issuer_key_id: grant.credential_issuer_key_id.clone(),
        credential_issuer_public_jwk: issuer_key,
        definition_id: grant.definition.id.clone(),
        definition_version: grant.definition.version.clone(),
        credential_type: grant.definition.credential_type.clone(),
        purpose: None,
    };
    (
        IssuerAuthorizations {
            version: 1,
            id: "https://trust.example/issuer-authorizations.jwt".into(),
            issuer: request.registry_did.clone(),
            iat: 100,
            exp: 200,
            authorizations: vec![grant],
        },
        request,
    )
}
#[test]
fn signed_authority_matches_exact_actual_issuer_version_and_key_and_expires() {
    let (document, mut request) = authority();
    let (signer, anchor) = signer(1);
    let header = serde_json::from_value::<JwsHeader>(json!({"alg":"ES256","typ":"issuer-authorizations+jwt","kid":"did:web:trust.example#key-1"})).unwrap();
    let signed =
        sign_issuer_authorizations(&document, &header, &signer, &KeyId::new("anchor")).unwrap();
    assert_eq!(
        verify_issuer_authorization(&signed, &anchor, &request, 150)
            .unwrap()
            .definition
            .id,
        "urn:example:membership"
    );
    assert_eq!(
        verify_issuer_authorization(&signed, &anchor, &request, 200)
            .unwrap_err()
            .code(),
        CoreErrorCode::FreshnessCheckFailed
    );
    request.definition_version = "2".into();
    assert_eq!(
        verify_issuer_authorization(&signed, &anchor, &request, 150)
            .unwrap_err()
            .code(),
        CoreErrorCode::TrustCheckFailed
    );
}

#[test]
fn actual_signed_credential_reference_cannot_be_replaced_by_copied_grant_scope() {
    use identity_core::{
        SubjectValidationMode, sign_compact_jws_json, verify_scalar_credential_authorization,
    };
    let (document, request) = authority();
    let (registry_signer, anchor) = signer(1);
    let (issuer_signer, issuer_key) = signer(2);
    let header: JwsHeader = serde_json::from_value(json!({"alg":"ES256","typ":"issuer-authorizations+jwt","kid":"did:web:trust.example#key-1"})).unwrap();
    let authorization =
        sign_issuer_authorizations(&document, &header, &registry_signer, &KeyId::new("anchor"))
            .unwrap();
    let vc_header: JwsHeader = serde_json::from_value(
        json!({"alg":"ES256","typ":"vc+sd-jwt","kid":"did:web:issuer.example#key-1"}),
    )
    .unwrap();
    let mut payload = json!({
        "@context":["https://www.w3.org/ns/credentials/v2",{"@vocab":"https://example.test/vocab#"}],
        "type":["VerifiableCredential","ExampleMembershipCredential"],
        "issuer":"did:web:issuer.example","iss":"did:web:issuer.example","iat":100,"exp":200,
        "validFrom":"1970-01-01T00:01:40Z","validUntil":"1970-01-01T00:03:20Z",
        "credentialDefinition":{"id":"urn:example:membership","version":"1"},
        "credentialSubject":{"member":true},"cnf":{"jwk":issuer_key},
        "credentialStatus":{"id":"https://status.example/1#0","type":"BitstringStatusListEntry","statusPurpose":"revocation","statusListIndex":"0","statusListCredential":"https://status.example/1"}
    });
    let token = format!(
        "{}~",
        sign_compact_jws_json(&vc_header, &payload, &issuer_signer, &KeyId::new("issuer")).unwrap()
    );
    verify_scalar_credential_authorization(
        &token,
        &request.credential_issuer_public_jwk,
        &authorization,
        &anchor,
        &request.registry_did,
        150,
        SubjectValidationMode::Complete,
    )
    .unwrap();
    payload["credentialDefinition"]["version"] = json!("2");
    let wrong = format!(
        "{}~",
        sign_compact_jws_json(&vc_header, &payload, &issuer_signer, &KeyId::new("issuer")).unwrap()
    );
    assert_eq!(
        verify_scalar_credential_authorization(
            &wrong,
            &request.credential_issuer_public_jwk,
            &authorization,
            &anchor,
            &request.registry_did,
            150,
            SubjectValidationMode::Complete
        )
        .unwrap_err()
        .code(),
        CoreErrorCode::TrustCheckFailed
    );
}

#[test]
fn definitions_refuse_protocol_aliases_unknown_vocabulary_and_ambiguous_paths() {
    let mut definition = definition();
    definition.claims[0].name = "vc".into();
    definition.profiles[0].claim_paths[0][1] = "vc".into();
    assert_eq!(
        validate_scalar_definition(&definition).unwrap_err().code(),
        CoreErrorCode::InvalidInput
    );
    let mut definition = self::definition();
    definition.profiles[0].claim_paths[0].push("nested".into());
    assert!(validate_scalar_definition(&definition).is_err());
    let mut unknown = serde_json::to_value(self::definition()).unwrap();
    unknown["schema_url"] = json!("https://schemas.example/anything");
    assert!(serde_json::from_value::<ScalarCredentialDefinition>(unknown).is_err());
}

#[test]
fn authorization_document_cannot_embed_conflicting_shared_definition_versions() {
    let (mut document, _) = authority();
    let mut second = document.authorizations[0].clone();
    second.credential_issuer_did = "did:web:other.example".into();
    second.credential_issuer_key_id = "did:web:other.example#key-1".into();
    second.definition.claims[0].value_type = identity_core::ScalarValueType::String;
    document.authorizations.push(second);
    let (signer, _) = signer(1);
    let header: JwsHeader=serde_json::from_value(json!({"alg":"ES256","typ":"issuer-authorizations+jwt","kid":"did:web:trust.example#key-1"})).unwrap();
    assert_eq!(
        sign_issuer_authorizations(&document, &header, &signer, &KeyId::new("anchor"))
            .unwrap_err()
            .code(),
        CoreErrorCode::TrustCheckFailed
    );
}

#[test]
fn scalar_definition_boundaries_refuse_duplicate_claims_paths_and_reserved_education() {
    let baseline = definition();
    let mut cases = Vec::new();
    let mut duplicate = baseline.clone();
    duplicate.claims.push(duplicate.claims[0].clone());
    cases.push(duplicate);
    let mut duplicate = baseline.clone();
    let path = duplicate.profiles[0].claim_paths[0].clone();
    duplicate.profiles[0].claim_paths.push(path);
    cases.push(duplicate);
    let mut reserved = baseline.clone();
    reserved.id = "urn:credworks:education".into();
    cases.push(reserved);
    let mut reserved = baseline.clone();
    reserved.credential_type = "UniversityEducationCredential".into();
    cases.push(reserved);
    let mut invalid = baseline.clone();
    invalid.max_validity_seconds = 31_536_001;
    cases.push(invalid);
    let mut invalid = baseline.clone();
    invalid.id = "https://user:password@issuer.example/definition".into();
    cases.push(invalid);
    let mut invalid = baseline.clone();
    invalid.id = "urn:example:".into();
    cases.push(invalid);
    for case in cases {
        assert_eq!(
            validate_scalar_definition(&case).unwrap_err().code(),
            CoreErrorCode::InvalidInput
        );
    }
    for value in [json!(null), json!([]), json!({}), json!(1)] {
        assert!(
            validate_scalar_subject(
                &baseline,
                &json!({"member":value}),
                SubjectValidationMode::Complete
            )
            .is_err()
        );
    }
}

#[test]
fn reserved_definition_namespace_cannot_be_aliased_by_uri_case() {
    let mut definition = definition();
    definition.id = "URN:CredWorks:education".into();
    assert_eq!(
        validate_scalar_definition(&definition).unwrap_err().code(),
        CoreErrorCode::InvalidInput
    );
}

#[test]
fn expired_predecessor_renewal_requires_current_exact_authority_without_restoring_validity() {
    use identity_core::{sign_compact_jws_json, verify_scalar_renewal_predecessor};
    let (mut document, request) = authority();
    document.iat = 250;
    document.exp = 350;
    let (registry_signer, anchor) = signer(1);
    let (issuer_signer, issuer_key) = signer(2);
    let registry_header: JwsHeader = serde_json::from_value(json!({"alg":"ES256","typ":"issuer-authorizations+jwt","kid":"did:web:trust.example#key-1"})).unwrap();
    let vc_header: JwsHeader = serde_json::from_value(
        json!({"alg":"ES256","typ":"vc+sd-jwt","kid":"did:web:issuer.example#key-1"}),
    )
    .unwrap();
    let payload = json!({
        "@context":["https://www.w3.org/ns/credentials/v2",{"@vocab":"https://example.test/vocab#"}],
        "type":["VerifiableCredential","ExampleMembershipCredential"],
        "issuer":"did:web:issuer.example","iss":"did:web:issuer.example","iat":100,"exp":200,
        "validFrom":"1970-01-01T00:01:40Z","validUntil":"1970-01-01T00:03:20Z",
        "credentialDefinition":{"id":"urn:example:membership","version":"1"},
        "credentialSubject":{"member":true},"cnf":{"jwk":issuer_key},
        "credentialStatus":{"id":"https://status.example/1#0","type":"BitstringStatusListEntry","statusPurpose":"revocation","statusListIndex":"0","statusListCredential":"https://status.example/1"}
    });
    let sign_credential = |payload: &serde_json::Value| {
        format!(
            "{}~",
            sign_compact_jws_json(&vc_header, payload, &issuer_signer, &KeyId::new("issuer"))
                .unwrap()
        )
    };
    let token = sign_credential(&payload);
    let sign_grant = |document: &IssuerAuthorizations| {
        sign_issuer_authorizations(
            document,
            &registry_header,
            &registry_signer,
            &KeyId::new("anchor"),
        )
        .unwrap()
    };
    let authorization = sign_grant(&document);
    assert_eq!(
        identity_core::verify_scalar_credential_authorization(
            &token,
            &issuer_key,
            &authorization,
            &anchor,
            &request.registry_did,
            300,
            SubjectValidationMode::Complete
        )
        .unwrap_err()
        .code(),
        CoreErrorCode::FreshnessCheckFailed
    );
    let verified = verify_scalar_renewal_predecessor(
        &token,
        &issuer_key,
        &authorization,
        &anchor,
        &request.registry_did,
        300,
    )
    .unwrap();
    assert_eq!(verified.processed_payload["iat"], json!(100));
    assert_eq!(verified.processed_payload["exp"], json!(200));
    assert_eq!(
        verified.processed_payload["credentialSubject"],
        json!({"member":true})
    );
    assert_eq!(
        verify_scalar_renewal_predecessor(
            &token,
            &issuer_key,
            &authorization,
            &anchor,
            &request.registry_did,
            350
        )
        .unwrap_err()
        .code(),
        CoreErrorCode::FreshnessCheckFailed
    );
    assert_eq!(
        verify_scalar_renewal_predecessor(
            &token,
            &issuer_key,
            &authorization,
            &anchor,
            &request.registry_did,
            249
        )
        .unwrap_err()
        .code(),
        CoreErrorCode::FreshnessCheckFailed
    );
    document.authorizations[0].status = identity_core::TrustListStatus::Inactive;
    assert_eq!(
        verify_scalar_renewal_predecessor(
            &token,
            &issuer_key,
            &sign_grant(&document),
            &anchor,
            &request.registry_did,
            300
        )
        .unwrap_err()
        .code(),
        CoreErrorCode::TrustCheckFailed
    );
    document.authorizations[0].status = identity_core::TrustListStatus::Active;
    document.authorizations[0].definition.version = "2".into();
    assert_eq!(
        verify_scalar_renewal_predecessor(
            &token,
            &issuer_key,
            &sign_grant(&document),
            &anchor,
            &request.registry_did,
            300
        )
        .unwrap_err()
        .code(),
        CoreErrorCode::TrustCheckFailed
    );
    let mut future = payload.clone();
    future["iat"] = json!(400);
    future["exp"] = json!(500);
    future["validFrom"] = json!("1970-01-01T00:06:40Z");
    future["validUntil"] = json!("1970-01-01T00:08:20Z");
    assert_eq!(
        verify_scalar_renewal_predecessor(
            &sign_credential(&future),
            &issuer_key,
            &authorization,
            &anchor,
            &request.registry_did,
            300
        )
        .unwrap_err()
        .code(),
        CoreErrorCode::FreshnessCheckFailed
    );
    let mut invalid = payload.clone();
    invalid["credentialSubject"]["member"] = json!("true");
    assert_eq!(
        verify_scalar_renewal_predecessor(
            &sign_credential(&invalid),
            &issuer_key,
            &authorization,
            &anchor,
            &request.registry_did,
            300
        )
        .unwrap_err()
        .code(),
        CoreErrorCode::InvalidInput
    );
    let (_, wrong_key) = signer(3);
    assert_eq!(
        verify_scalar_renewal_predecessor(
            &token,
            &wrong_key,
            &authorization,
            &anchor,
            &request.registry_did,
            300
        )
        .unwrap_err()
        .code(),
        CoreErrorCode::InvalidSignature
    );
}

#[test]
fn shared_definition_adoption_grants_only_each_explicit_issuer_and_key() {
    let (mut document, mut request) = authority();
    let (_, adopted_key) = signer(3);
    let mut adopted = document.authorizations[0].clone();
    adopted.credential_issuer_did = "did:web:adopter.example".into();
    adopted.credential_issuer_key_id = "did:web:adopter.example#key-1".into();
    adopted.credential_issuer_public_jwk_sha256_thumbprint =
        public_jwk_sha256_thumbprint(&adopted_key).unwrap();
    document.authorizations.push(adopted.clone());
    let (signer, anchor) = signer(1);
    let header: JwsHeader = serde_json::from_value(json!({"alg":"ES256","typ":"issuer-authorizations+jwt","kid":"did:web:trust.example#key-1"})).unwrap();
    let signed =
        sign_issuer_authorizations(&document, &header, &signer, &KeyId::new("anchor")).unwrap();
    verify_issuer_authorization(&signed, &anchor, &request, 150).unwrap();
    request.credential_issuer_did = adopted.credential_issuer_did;
    request.credential_issuer_key_id = adopted.credential_issuer_key_id;
    assert_eq!(
        verify_issuer_authorization(&signed, &anchor, &request, 150)
            .unwrap_err()
            .code(),
        CoreErrorCode::TrustCheckFailed
    );
    request.credential_issuer_public_jwk = adopted_key;
    verify_issuer_authorization(&signed, &anchor, &request, 150).unwrap();
}
