use identity_core::{
    CoreErrorCode, IssuerAuthorizationRequest, IssuerAuthorizations, JwsHeader, KeyId, KeyStore,
    LocalSigner, PublicJwk, public_jwk_sha256_thumbprint, sign_compact_jws_json,
    sign_issuer_authorizations, verify_issuer_authorization,
};
use serde_json::{Value, json};

const ISSUER: &str = "did:web:issuer.example";
const REGISTRY: &str = "did:web:trust.example";

fn definition() -> Value {
    json!({
        "id":"urn:example:membership","version":"1","credential_type":"ExampleMembershipCredential",
        "label":"Membership","max_validity_seconds":3600,
        "claims":[{"name":"member","label":"Member","value_type":"boolean","required":true}],
        "profiles":[{"name":"access","claim_paths":[["credentialSubject","member"]]}]
    })
}

struct Authority {
    registry: LocalSigner,
    anchor: PublicJwk,
    old_key: PublicJwk,
    new_key: PublicJwk,
    document: Value,
}
impl Authority {
    fn new() -> Self {
        let registry_id = KeyId::new(format!("{REGISTRY}#registry"));
        let registry = LocalSigner::generate(registry_id.clone()).unwrap();
        let anchor = registry.public_jwk(&registry_id).unwrap();
        let old_id = KeyId::new(format!("{ISSUER}#bootstrap"));
        let old_key = LocalSigner::generate(old_id.clone())
            .unwrap()
            .public_jwk(&old_id)
            .unwrap();
        let new_id = KeyId::new(format!("{ISSUER}#credential-2"));
        let new_key = LocalSigner::generate(new_id.clone())
            .unwrap()
            .public_jwk(&new_id)
            .unwrap();
        let status = json!({"key_id":old_id.as_str(),"public_jwk_sha256_thumbprint":public_jwk_sha256_thumbprint(&old_key).unwrap()});
        let entry = |key_id: &KeyId, key: &PublicJwk, state: &str| {
            json!({
                "credential_issuer_did":ISSUER,"credential_issuer_key_id":key_id.as_str(),
                "credential_issuer_public_jwk_sha256_thumbprint":public_jwk_sha256_thumbprint(key).unwrap(),
                "definition":definition(),"status":"active","key_state":state,"status_authority":status
            })
        };
        let document = json!({"version":1,"id":"https://trust.example/authorizations.jwt","issuer":REGISTRY,
            "iat":100,"exp":200,"authorizations":[entry(&old_id,&old_key,"retained"),entry(&new_id,&new_key,"current")]});
        Self {
            registry,
            anchor,
            old_key,
            new_key,
            document,
        }
    }
    fn sign(&self) -> identity_core::CoreResult<String> {
        let document: IssuerAuthorizations = serde_json::from_value(self.document.clone()).unwrap();
        let header: JwsHeader = serde_json::from_value(json!({"alg":"ES256","typ":"issuer-authorizations+jwt","kid":format!("{REGISTRY}#registry")})).unwrap();
        sign_issuer_authorizations(
            &document,
            &header,
            &self.registry,
            &KeyId::new(format!("{REGISTRY}#registry")),
        )
    }
    fn request(&self, old: bool, purpose: Option<&str>) -> IssuerAuthorizationRequest {
        let mut request = json!({"registry_did":REGISTRY,"credential_issuer_did":ISSUER,
            "credential_issuer_key_id":format!("{ISSUER}#{}",if old {"bootstrap"} else {"credential-2"}),
            "credential_issuer_public_jwk":if old {&self.old_key} else {&self.new_key},
            "definition_id":"urn:example:membership","definition_version":"1","credential_type":"ExampleMembershipCredential"});
        if let Some(purpose) = purpose {
            request["purpose"] = json!(purpose);
        }
        serde_json::from_value(request).unwrap()
    }
    fn sign_unchecked(&self) -> String {
        let header: JwsHeader = serde_json::from_value(json!({"alg":"ES256","typ":"issuer-authorizations+jwt","kid":format!("{REGISTRY}#registry")})).unwrap();
        sign_compact_jws_json(
            &header,
            &self.document,
            &self.registry,
            &KeyId::new(format!("{REGISTRY}#registry")),
        )
        .unwrap()
    }
}

#[test]
fn ambiguous_or_reassigned_history_refuses_even_when_authentically_signed() {
    let authority = Authority::new();
    let mut cases = vec![];
    let mut doc = authority.document.clone();
    doc["authorizations"][0]["key_state"] = json!("current");
    cases.push(doc); // Two distinct current keys.
    let mut doc = authority.document.clone();
    doc["authorizations"][1]
        .as_object_mut()
        .unwrap()
        .remove("key_state");
    doc["authorizations"][1]
        .as_object_mut()
        .unwrap()
        .remove("status_authority");
    cases.push(doc); // Implicit legacy entry mixed with explicit history.
    for field in [
        "credential_issuer_public_jwk_sha256_thumbprint",
        "key_state",
    ] {
        let mut doc = authority.document.clone();
        let mut alternate = doc["authorizations"][0].clone();
        alternate["definition"]["version"] = json!("2");
        alternate[field] = if field == "key_state" {
            json!("withdrawn")
        } else {
            doc["authorizations"][1][field].clone()
        };
        doc["authorizations"]
            .as_array_mut()
            .unwrap()
            .push(alternate);
        cases.push(doc); // Same key ID reassigned across definitions.
    }
    let mut doc = authority.document.clone();
    doc["authorizations"][1]["status_authority"]["key_id"] =
        json!(format!("{ISSUER}#credential-2"));
    doc["authorizations"][1]["status_authority"]["public_jwk_sha256_thumbprint"] =
        json!(public_jwk_sha256_thumbprint(&authority.new_key).unwrap());
    cases.push(doc); // Conflicting status authority for one DID.
    for document in cases {
        let malformed = Authority {
            document,
            ..Authority::new()
        };
        assert_eq!(
            malformed.sign().unwrap_err().code(),
            CoreErrorCode::TrustCheckFailed
        );
        let compact = malformed.sign_unchecked();
        assert_eq!(
            verify_issuer_authorization(
                &compact,
                &malformed.anchor,
                &authority.request(true, Some("verification")),
                150
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::TrustCheckFailed
        );
    }
}

#[test]
fn retained_key_verifies_but_cannot_issue_and_returns_authenticated_status_authority() {
    let authority = Authority::new();
    let compact = authority.sign().unwrap();
    let verified = verify_issuer_authorization(
        &compact,
        &authority.anchor,
        &authority.request(true, Some("verification")),
        150,
    )
    .unwrap();
    let result = serde_json::to_value(verified).unwrap();
    assert_eq!(result["key_state"], "retained");
    assert_eq!(
        result["status_authority"],
        authority.document["authorizations"][0]["status_authority"]
    );
    for purpose in [None, Some("issuance")] {
        assert_eq!(
            verify_issuer_authorization(
                &compact,
                &authority.anchor,
                &authority.request(true, purpose),
                150
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::TrustCheckFailed
        );
    }
    for purpose in [None, Some("issuance"), Some("verification")] {
        verify_issuer_authorization(
            &compact,
            &authority.anchor,
            &authority.request(false, purpose),
            150,
        )
        .unwrap();
    }
}

#[test]
fn explicit_null_is_not_legacy_omission() {
    let authority = Authority::new();
    let mut document = authority.document.clone();
    document["authorizations"][0]["key_state"] = Value::Null;
    document["authorizations"][0]["status_authority"] = Value::Null;
    assert!(serde_json::from_value::<IssuerAuthorizations>(document).is_err());
    let mut request = serde_json::to_value(authority.request(true, None)).unwrap();
    request["purpose"] = Value::Null;
    assert!(serde_json::from_value::<IssuerAuthorizationRequest>(request).is_err());
}

#[test]
fn withdrawal_inactivity_exact_scope_and_expiry_refuse_without_rebinding() {
    let mut authority = Authority::new();
    let original = authority.sign().unwrap();
    authority.document["authorizations"][0]["key_state"] = json!("withdrawn");
    let withdrawn = authority.sign().unwrap();
    for purpose in [None, Some("issuance"), Some("verification")] {
        assert_eq!(
            verify_issuer_authorization(
                &withdrawn,
                &authority.anchor,
                &authority.request(true, purpose),
                150
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::TrustCheckFailed
        );
    }
    verify_issuer_authorization(
        &withdrawn,
        &authority.anchor,
        &authority.request(false, None),
        150,
    )
    .unwrap();
    // Original evidence remains independently authenticatable at its observation time.
    verify_issuer_authorization(
        &original,
        &authority.anchor,
        &authority.request(true, Some("verification")),
        150,
    )
    .unwrap();
    authority.document["authorizations"][1]["status"] = json!("inactive");
    let inactive = authority.sign().unwrap();
    for purpose in [None, Some("verification")] {
        assert_eq!(
            verify_issuer_authorization(
                &inactive,
                &authority.anchor,
                &authority.request(false, purpose),
                150
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::TrustCheckFailed
        );
    }
    for now in [99, 200] {
        assert_eq!(
            verify_issuer_authorization(
                &original,
                &authority.anchor,
                &authority.request(true, Some("verification")),
                now
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::FreshnessCheckFailed
        );
    }
    for (field, value) in [
        ("credential_issuer_did", json!("did:web:other.example")),
        (
            "credential_issuer_key_id",
            json!(format!("{ISSUER}#credential-2")),
        ),
        ("credential_issuer_public_jwk", json!(authority.new_key)),
        ("definition_id", json!("urn:example:other")),
        ("definition_version", json!("2")),
        ("credential_type", json!("OtherCredential")),
    ] {
        let mut request =
            serde_json::to_value(authority.request(true, Some("verification"))).unwrap();
        request[field] = value;
        let request = serde_json::from_value(request).unwrap();
        assert_eq!(
            verify_issuer_authorization(&original, &authority.anchor, &request, 150)
                .unwrap_err()
                .code(),
            CoreErrorCode::TrustCheckFailed
        );
    }
}

#[test]
fn malformed_status_authority_and_unpaired_fields_refuse() {
    let authority = Authority::new();
    let mut cases = vec![];
    for field in ["key_state", "status_authority"] {
        let mut document = authority.document.clone();
        document["authorizations"][0]
            .as_object_mut()
            .unwrap()
            .remove(field);
        cases.push(document);
    }
    for (field, value) in [
        ("key_id", json!("did:web:other.example#bootstrap")),
        ("key_id", json!(format!("{ISSUER}#"))),
        ("key_id", json!(format!("{ISSUER}#bad/fragment"))),
        ("public_jwk_sha256_thumbprint", json!("short")),
        (
            "public_jwk_sha256_thumbprint",
            json!(public_jwk_sha256_thumbprint(&authority.new_key).unwrap()),
        ),
    ] {
        let mut document = authority.document.clone();
        for entry in document["authorizations"].as_array_mut().unwrap() {
            entry["status_authority"][field] = value.clone();
        }
        cases.push(document);
    }
    for document in cases {
        let malformed = Authority {
            document,
            ..Authority::new()
        };
        assert_eq!(
            malformed.sign().unwrap_err().code(),
            CoreErrorCode::TrustCheckFailed
        );
        assert_eq!(
            verify_issuer_authorization(
                &malformed.sign_unchecked(),
                &malformed.anchor,
                &authority.request(true, Some("verification")),
                150
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::TrustCheckFailed
        );
    }
    let mut document = authority.document.clone();
    document["authorizations"][0]["key_state"] = json!("retired");
    assert!(serde_json::from_value::<IssuerAuthorizations>(document).is_err());
    let mut request = serde_json::to_value(authority.request(true, None)).unwrap();
    request["purpose"] = json!("historical");
    assert!(serde_json::from_value::<IssuerAuthorizationRequest>(request).is_err());
}

#[test]
fn legacy_bytes_and_actual_credential_verification_preserve_compatibility() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../vectors/conformance/scalar-definitions.json"
    ))
    .unwrap();
    let document: IssuerAuthorizations =
        serde_json::from_value(fixture["document"].clone()).unwrap();
    assert_eq!(
        serde_json::to_value(&document).unwrap(),
        fixture["document"]
    );
    let request: IssuerAuthorizationRequest =
        serde_json::from_value(fixture["request"].clone()).unwrap();
    assert_eq!(serde_json::to_value(&request).unwrap(), fixture["request"]);
    let anchor = serde_json::from_value(fixture["anchor"].clone()).unwrap();
    let result = verify_issuer_authorization(
        fixture["compact_authorization"].as_str().unwrap(),
        &anchor,
        &request,
        150,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(result).unwrap(),
        fixture["document"]["authorizations"][0]
    );

    let mut authority = Authority::new();
    authority.document = fixture["document"].clone();
    let grant = &mut authority.document["authorizations"][0];
    grant["key_state"] = json!("retained");
    grant["status_authority"] = json!({"key_id":grant["credential_issuer_key_id"],"public_jwk_sha256_thumbprint":grant["credential_issuer_public_jwk_sha256_thumbprint"]});
    let issuer = serde_json::from_value(fixture["issuer_jwk"].clone()).unwrap();
    let verify = |compact: &str| {
        identity_core::verify_scalar_credential_authorization(
            fixture["compact_credential"].as_str().unwrap(),
            &issuer,
            compact,
            &authority.anchor,
            REGISTRY,
            150,
            identity_core::SubjectValidationMode::Complete,
        )
    };
    verify(&authority.sign().unwrap()).unwrap();
    authority.document["authorizations"][0]["key_state"] = json!("withdrawn");
    assert_eq!(
        verify(&authority.sign().unwrap()).unwrap_err().code(),
        CoreErrorCode::TrustCheckFailed
    );
}

#[test]
fn explicit_authority_preserves_existing_document_count_and_lifetime_bounds() {
    let mut authority = Authority::new();
    let current = authority.document["authorizations"][1].clone();
    authority.document["authorizations"] = (1..=64)
        .map(|version| {
            let mut grant = current.clone();
            grant["definition"]["version"] = json!(version.to_string());
            grant
        })
        .collect();
    authority.document["exp"] = json!(86_500);
    let compact = authority.sign().unwrap();
    verify_issuer_authorization(
        &compact,
        &authority.anchor,
        &authority.request(false, None),
        86_499,
    )
    .unwrap();
    assert_eq!(
        verify_issuer_authorization(
            &compact,
            &authority.anchor,
            &authority.request(false, None),
            86_500
        )
        .unwrap_err()
        .code(),
        CoreErrorCode::FreshnessCheckFailed
    );
    authority.document["exp"] = json!(86_501);
    assert_eq!(
        authority.sign().unwrap_err().code(),
        CoreErrorCode::TrustCheckFailed
    );
    authority.document["exp"] = json!(200);
    let mut extra = current;
    extra["definition"]["version"] = json!("65");
    authority.document["authorizations"]
        .as_array_mut()
        .unwrap()
        .push(extra);
    assert_eq!(
        authority.sign().unwrap_err().code(),
        CoreErrorCode::TrustCheckFailed
    );
    assert_eq!(
        verify_issuer_authorization(
            &authority.sign_unchecked(),
            &authority.anchor,
            &authority.request(false, None),
            150
        )
        .unwrap_err()
        .code(),
        CoreErrorCode::TrustCheckFailed
    );
}

#[test]
fn rust_authenticates_portable_old_new_credentials_and_separate_status_key() {
    let v: Value = serde_json::from_str(include_str!(
        "../../../vectors/conformance/issuer-key-authority.json"
    ))
    .unwrap();
    let anchor: PublicJwk = serde_json::from_value(v["anchor"].clone()).unwrap();
    let bootstrap: PublicJwk = serde_json::from_value(v["bootstrap"].clone()).unwrap();
    let current: PublicJwk = serde_json::from_value(v["current"].clone()).unwrap();
    for (name, key) in [("old_credential", &bootstrap), ("new_credential", &current)] {
        identity_core::verify_scalar_credential_authorization(
            v[name].as_str().unwrap(),
            key,
            v["compact_authorization"].as_str().unwrap(),
            &anchor,
            REGISTRY,
            150,
            identity_core::SubjectValidationMode::Complete,
        )
        .unwrap();
    }
    assert_eq!(
        identity_core::verify_scalar_credential_authorization(
            v["old_credential"].as_str().unwrap(),
            &bootstrap,
            v["withdrawn_authorization"].as_str().unwrap(),
            &anchor,
            REGISTRY,
            150,
            identity_core::SubjectValidationMode::Complete
        )
        .unwrap_err()
        .code(),
        CoreErrorCode::TrustCheckFailed
    );
    let request = serde_json::from_value(v["new_request"].clone()).unwrap();
    let grant = verify_issuer_authorization(
        v["withdrawn_authorization"].as_str().unwrap(),
        &anchor,
        &request,
        150,
    )
    .unwrap();
    let authority = grant.status_authority.unwrap();
    let (header, payload) = identity_core::verify_bitstring_status_list_credential_at(
        v["revoked_status"].as_str().unwrap(),
        &bootstrap,
        150,
    )
    .unwrap();
    assert_eq!(header.kid.as_deref(), Some(authority.key_id.as_str()));
    assert_eq!(
        public_jwk_sha256_thumbprint(&bootstrap).unwrap(),
        authority.public_jwk_sha256_thumbprint
    );
    assert_eq!(payload.issuer, ISSUER);
    assert!(
        identity_core::bitstring_status_at(&payload.credential_subject.encoded_list, 0).unwrap()
    );
    assert_eq!(
        identity_core::verify_bitstring_status_list_credential_at(
            v["revoked_status"].as_str().unwrap(),
            &current,
            150
        )
        .unwrap_err()
        .code(),
        CoreErrorCode::InvalidSignature
    );
}
