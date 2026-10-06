use identity_core::{
    CoreResult, JwsHeader, KeyId, PublicJwk, ScopedVerifierPermission,
    ScopedVerifierPermissionRequest, ScopedVerifierPermissions, Signer, b64_encode,
    public_jwk_sha256_thumbprint, sign_scoped_verifier_permissions,
    verify_scoped_verifier_permission,
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
fn fixture() -> (ScopedVerifierPermissions, ScopedVerifierPermissionRequest) {
    let (_, verifier) = signer(2);
    let paths = vec![
        vec!["credentialSubject".into(), "enrolled".into()],
        vec!["credentialSubject".into(), "institution_id".into()],
    ];
    let grant = ScopedVerifierPermission {
        credential_issuer_did: "did:web:issuer-unsw.credworks.xyz".into(),
        definition_id: "urn:credworks:education".into(),
        definition_version: "1".into(),
        credential_type: "UniversityEducationCredential".into(),
        verifier_did: "did:web:partner.example".into(),
        verifier_origin: "https://partner.example".into(),
        verifier_public_jwk_sha256_thumbprint: public_jwk_sha256_thumbprint(&verifier).unwrap(),
        profile_name: "education_eligibility".into(),
        claim_paths: paths.clone(),
        status: identity_core::TrustListStatus::Active,
    };
    let request = ScopedVerifierPermissionRequest {
        credential_issuer_did: grant.credential_issuer_did.clone(),
        definition_id: grant.definition_id.clone(),
        definition_version: grant.definition_version.clone(),
        credential_type: grant.credential_type.clone(),
        verifier_did: grant.verifier_did.clone(),
        verifier_origin: grant.verifier_origin.clone(),
        verifier_public_jwk: verifier,
        profile_name: grant.profile_name.clone(),
        claim_paths: paths,
    };
    (
        ScopedVerifierPermissions {
            version: 1,
            id: "https://trust.credworks.xyz/verifier-permissions.jwt".into(),
            issuer: "did:web:trust.credworks.xyz".into(),
            iat: 100,
            exp: 200,
            permissions: vec![grant],
        },
        request,
    )
}
fn header() -> JwsHeader {
    serde_json::from_value(
        serde_json::json!({"alg":"ES256","typ":"scoped-verifier-permissions+jwt","kid":"anchor"}),
    )
    .unwrap()
}
#[test]
fn exact_education_scope_verifies_with_pinned_anchor_and_only_requested_paths() {
    let (document, mut request) = fixture();
    let (signer, anchor) = signer(1);
    let compact =
        sign_scoped_verifier_permissions(&document, &header(), &signer, &KeyId::new("anchor"))
            .unwrap();
    request.claim_paths.truncate(1);
    let result = verify_scoped_verifier_permission(&compact, &anchor, &request, 150).unwrap();
    assert_eq!(
        result.claim_paths,
        vec![vec!["credentialSubject".to_owned(), "enrolled".to_owned()]]
    );
    assert!(result.active);
}

#[test]
fn signing_refuses_ambiguous_or_unsupported_permission_shapes() {
    let (document, _) = fixture();
    let (signer, _) = signer(1);
    let mut invalids = Vec::new();
    let mut duplicate = document.clone();
    duplicate.permissions.push(duplicate.permissions[0].clone());
    invalids.push(duplicate);
    for paths in [
        vec![],
        vec![vec!["credentialSubject"]],
        vec![
            vec!["credentialSubject", "name"],
            vec!["credentialSubject", "name", "given"],
        ],
        vec![vec!["credentialSubject", "*"]],
        vec![vec!["credentialSubject", "items", "0"]],
        vec![vec!["iss"]],
        vec![
            vec!["credentialSubject", "enrolled"],
            vec!["credentialSubject", "enrolled"],
        ],
    ] {
        let mut changed = document.clone();
        changed.permissions[0].claim_paths = paths
            .into_iter()
            .map(|path| path.into_iter().map(str::to_owned).collect())
            .collect();
        invalids.push(changed);
    }
    for field in [
        "credential_issuer_did",
        "definition_id",
        "definition_version",
        "credential_type",
        "verifier_did",
        "verifier_origin",
        "verifier_public_jwk_sha256_thumbprint",
        "profile_name",
    ] {
        let mut value = serde_json::to_value(&document).unwrap();
        value["permissions"][0][field] = "".into();
        invalids.push(serde_json::from_value(value).unwrap());
    }
    let mut insecure_origin = document.clone();
    insecure_origin.permissions[0].verifier_origin = "http://partner.example".into();
    invalids.push(insecure_origin);
    let mut wrong_origin = document.clone();
    wrong_origin.permissions[0].verifier_origin = "https://other.example".into();
    invalids.push(wrong_origin);
    for invalid in invalids {
        assert_eq!(
            sign_scoped_verifier_permissions(&invalid, &header(), &signer, &KeyId::new("anchor"))
                .unwrap_err()
                .code(),
            identity_core::CoreErrorCode::TrustCheckFailed
        );
    }
}

#[test]
fn verification_names_signature_scope_and_freshness_failures_and_legacy_refuses() {
    use identity_core::{
        CoreErrorCode, sign_compact_jws_json, verify_trust_list,
        verify_verifier_trust_list_accreditation,
    };
    let (document, request) = fixture();
    let (signer, anchor) = signer(1);
    let compact =
        sign_scoped_verifier_permissions(&document, &header(), &signer, &KeyId::new("anchor"))
            .unwrap();
    for now in [99, 200, 201] {
        assert_eq!(
            verify_scoped_verifier_permission(&compact, &anchor, &request, now)
                .unwrap_err()
                .code(),
            CoreErrorCode::TrustCheckFailed
        );
    }
    let (_, wrong_anchor) = self::signer(3);
    assert_eq!(
        verify_scoped_verifier_permission(&compact, &wrong_anchor, &request, 150)
            .unwrap_err()
            .code(),
        CoreErrorCode::InvalidSignature
    );
    let mut parts: Vec<_> = compact.split('.').map(str::to_owned).collect();
    let mut signature = identity_core::b64_decode(&parts[2]).unwrap();
    signature[0] ^= 1;
    parts[2] = b64_encode(&signature);
    assert_eq!(
        verify_scoped_verifier_permission(&parts.join("."), &anchor, &request, 150)
            .unwrap_err()
            .code(),
        CoreErrorCode::InvalidSignature
    );
    for (field, replacement) in [
        ("credential_issuer_did", "did:web:another.example"),
        ("definition_id", "urn:other:education"),
        ("definition_version", "2"),
        ("credential_type", "OtherCredential"),
        ("verifier_did", "did:web:another.example"),
        ("verifier_origin", "https://another.example"),
        ("profile_name", "education_sign_in"),
    ] {
        let mut value = serde_json::to_value(&request).unwrap();
        value[field] = replacement.into();
        let changed = serde_json::from_value(value).unwrap();
        assert_eq!(
            verify_scoped_verifier_permission(&compact, &anchor, &changed, 150)
                .unwrap_err()
                .code(),
            CoreErrorCode::TrustCheckFailed
        );
    }
    let mut wrong_key = request.clone();
    wrong_key.verifier_public_jwk = wrong_anchor;
    assert_eq!(
        verify_scoped_verifier_permission(&compact, &anchor, &wrong_key, 150)
            .unwrap_err()
            .code(),
        CoreErrorCode::TrustCheckFailed
    );
    for path in [
        vec!["credentialSubject", "student_id"],
        vec!["credentialSubject", "nested", "enrolled"],
    ] {
        let mut changed = request.clone();
        changed.claim_paths = vec![path.into_iter().map(str::to_owned).collect()];
        assert_eq!(
            verify_scoped_verifier_permission(&compact, &anchor, &changed, 150)
                .unwrap_err()
                .code(),
            CoreErrorCode::TrustCheckFailed
        );
    }
    for version in [0, 2] {
        let mut changed = document.clone();
        changed.version = version;
        let unsupported =
            sign_compact_jws_json(&header(), &changed, &signer, &KeyId::new("anchor")).unwrap();
        assert_eq!(
            verify_scoped_verifier_permission(&unsupported, &anchor, &request, 150)
                .unwrap_err()
                .code(),
            CoreErrorCode::TrustCheckFailed
        );
    }
    assert_eq!(
        verify_trust_list(&compact, &anchor).unwrap_err().code(),
        CoreErrorCode::TrustCheckFailed
    );
    assert!(
        verify_verifier_trust_list_accreditation(
            &compact,
            &anchor,
            &request.verifier_did,
            &request.credential_type,
            &request.profile_name,
            &request.claim_paths,
            150
        )
        .is_err()
    );
}

#[test]
fn nested_paths_remain_exact_and_empty_or_inactive_documents_grant_nothing() {
    use identity_core::CoreErrorCode;
    let (mut document, mut request) = fixture();
    let (signer, anchor) = signer(1);
    document.permissions[0].claim_paths = vec![
        vec!["credentialSubject".into(), "home".into(), "name".into()],
        vec!["credentialSubject".into(), "office".into(), "name".into()],
        vec!["credentialSubject".into(), "members".into()],
    ];
    request.claim_paths = vec![document.permissions[0].claim_paths[0].clone()];
    let compact =
        sign_scoped_verifier_permissions(&document, &header(), &signer, &KeyId::new("anchor"))
            .unwrap();
    assert_eq!(
        verify_scoped_verifier_permission(&compact, &anchor, &request, 150)
            .unwrap()
            .claim_paths,
        request.claim_paths
    );
    request.claim_paths[0][1] = "school".into();
    assert_eq!(
        verify_scoped_verifier_permission(&compact, &anchor, &request, 150)
            .unwrap_err()
            .code(),
        CoreErrorCode::TrustCheckFailed
    );
    document.permissions[0].status = identity_core::TrustListStatus::Inactive;
    let compact =
        sign_scoped_verifier_permissions(&document, &header(), &signer, &KeyId::new("anchor"))
            .unwrap();
    assert_eq!(
        verify_scoped_verifier_permission(&compact, &anchor, &request, 150)
            .unwrap_err()
            .code(),
        CoreErrorCode::TrustCheckFailed
    );
    document.permissions.clear();
    let compact =
        sign_scoped_verifier_permissions(&document, &header(), &signer, &KeyId::new("anchor"))
            .unwrap();
    assert_eq!(
        verify_scoped_verifier_permission(&compact, &anchor, &request, 150)
            .unwrap_err()
            .code(),
        CoreErrorCode::TrustCheckFailed
    );
}

#[test]
fn signing_rejects_invalid_did_urn_and_excessive_lifetime() {
    let (document, _) = fixture();
    let (signer, _) = signer(1);
    for (field, value) in [
        ("credential_issuer_did", "did:web:user@issuer.example"),
        ("credential_issuer_did", "did:web:issuer.example/path"),
        ("definition_id", "urn::education"),
        ("definition_id", "urn:credworks:"),
        ("definition_id", "urn:credworks:education bad"),
    ] {
        let mut changed = serde_json::to_value(&document).unwrap();
        changed["permissions"][0][field] = value.into();
        let changed = serde_json::from_value(changed).unwrap();
        assert_eq!(
            sign_scoped_verifier_permissions(&changed, &header(), &signer, &KeyId::new("anchor"))
                .unwrap_err()
                .code(),
            identity_core::CoreErrorCode::TrustCheckFailed
        );
    }
    let mut excessive = document;
    excessive.exp = excessive.iat + 86401;
    assert_eq!(
        sign_scoped_verifier_permissions(&excessive, &header(), &signer, &KeyId::new("anchor"))
            .unwrap_err()
            .code(),
        identity_core::CoreErrorCode::TrustCheckFailed
    );
}
