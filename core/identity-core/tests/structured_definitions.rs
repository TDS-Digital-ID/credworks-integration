use identity_core::{
    CoreErrorCode, ScalarCredentialDefinition, SubjectValidationMode, validate_scalar_definition,
    validate_scalar_subject,
};
use serde_json::{Value, json};

fn nested_definition_json() -> Value {
    json!({
        "id":"urn:example:structured","version":"1","credential_type":"ExampleStructuredCredential",
        "label":"Structured","max_validity_seconds":3600,
        "claims":[
            {"name":"name","path":["credentialSubject","left","name"],"label":"Left name","value_type":"string","required":true},
            {"name":"name","path":["credentialSubject","right","name"],"label":"Right name","value_type":"string","required":true}
        ],
        "profiles":[
            {"name":"left_only","claim_paths":[["credentialSubject","left","name"]]},
            {"name":"both","claim_paths":[["credentialSubject","left","name"],["credentialSubject","right","name"]]}
        ]
    })
}

#[test]
fn nested_same_leaf_names_validate_by_exact_path_without_colliding() {
    let definition: ScalarCredentialDefinition =
        serde_json::from_value(nested_definition_json()).unwrap();
    validate_scalar_definition(&definition).unwrap();
    validate_scalar_subject(
        &definition,
        &json!({"left":{"name":"North"},"right":{"name":"South"}}),
        SubjectValidationMode::Complete,
    )
    .unwrap();
    validate_scalar_subject(
        &definition,
        &json!({"left":{"name":"North"}}),
        SubjectValidationMode::Disclosed,
    )
    .unwrap();
    assert_eq!(
        validate_scalar_subject(
            &definition,
            &json!({"left":{"name":"North"}}),
            SubjectValidationMode::Complete
        )
        .unwrap_err()
        .code(),
        CoreErrorCode::InvalidInput
    );
    assert_eq!(
        validate_scalar_subject(
            &definition,
            &json!({"left":{"name":"North","extra":"secret"},"right":{"name":"South"}}),
            SubjectValidationMode::Complete
        )
        .unwrap_err()
        .code(),
        CoreErrorCode::InvalidInput
    );
}

fn whole_definition_json() -> Value {
    let mut definition = nested_definition_json();
    definition["claims"].as_array_mut().unwrap().extend([
        json!({"name":"details","label":"Complete details","value_type":"object","required":true}),
        json!({"name":"entries","label":"Complete entries","value_type":"array","required":true}),
    ]);
    definition["profiles"].as_array_mut().unwrap().push(json!({"name":"whole","claim_paths":[["credentialSubject","details"],["credentialSubject","entries"]]}));
    definition
}
fn whole_subject() -> Value {
    json!({"left":{"name":"North"},"right":{"name":"South"},"details":{"settings":{"enabled":false},"count":7},"entries":[{"label":"Example","enabled":false},3.5,["a",true]]})
}
#[test]
fn complete_object_and_array_values_validate_without_type_specific_fields() {
    let definition: ScalarCredentialDefinition =
        serde_json::from_value(whole_definition_json()).unwrap();
    validate_scalar_definition(&definition).unwrap();
    validate_scalar_subject(
        &definition,
        &whole_subject(),
        SubjectValidationMode::Complete,
    )
    .unwrap();
    validate_scalar_subject(
        &definition,
        &json!({"entries": []}),
        SubjectValidationMode::Disclosed,
    )
    .unwrap();
    let mut subject = whole_subject();
    subject["details"] = json!([]);
    assert_eq!(
        validate_scalar_subject(&definition, &subject, SubjectValidationMode::Complete)
            .unwrap_err()
            .code(),
        CoreErrorCode::InvalidInput
    );
}

fn one_claim_definition(value_type: &str, path: &[&str]) -> ScalarCredentialDefinition {
    let mut definition = nested_definition_json();
    definition["claims"] = json!([{"name":path.last().unwrap(),"path":path,"label":"Whole value","value_type":value_type,"required":true}]);
    definition["profiles"] = json!([{"name":"whole","claim_paths":[path]}]);
    serde_json::from_value(definition).unwrap()
}
fn wrapped(mut value: Value, levels: usize) -> Value {
    for _ in 0..levels {
        value = json!({"value":value});
    }
    value
}
#[test]
fn declared_path_and_whole_value_share_the_total_subject_depth_allowance() {
    let definition = one_claim_definition(
        "object",
        &["credentialSubject", "level_one", "level_two", "details"],
    );
    validate_scalar_subject(
        &definition,
        &json!({"level_one":{"level_two":{"details":wrapped(json!(true),12)}}}),
        SubjectValidationMode::Complete,
    )
    .unwrap();
    assert_eq!(
        validate_scalar_subject(
            &definition,
            &json!({"level_one":{"level_two":{"details":wrapped(json!(true),13)}}}),
            SubjectValidationMode::Complete
        )
        .unwrap_err()
        .code(),
        CoreErrorCode::InvalidInput
    );
}

#[test]
fn whole_values_enforce_immediate_entry_total_node_and_utf8_byte_limits() {
    let array_definition = one_claim_definition("array", &["credentialSubject", "entries"]);
    validate_scalar_subject(
        &array_definition,
        &json!({"entries":vec![true;64]}),
        SubjectValidationMode::Complete,
    )
    .unwrap();
    assert_eq!(
        validate_scalar_subject(
            &array_definition,
            &json!({"entries":vec![true;65]}),
            SubjectValidationMode::Complete
        )
        .unwrap_err()
        .code(),
        CoreErrorCode::InvalidInput
    );
    let object_definition = one_claim_definition("object", &["credentialSubject", "details"]);
    let mut properties = serde_json::Map::new();
    for index in 0..64 {
        properties.insert(format!("field_{index}"), json!(true));
    }
    validate_scalar_subject(
        &object_definition,
        &json!({"details":properties}),
        SubjectValidationMode::Complete,
    )
    .unwrap();
    properties.insert("another".into(), json!(true));
    assert_eq!(
        validate_scalar_subject(
            &object_definition,
            &json!({"details":properties}),
            SubjectValidationMode::Complete
        )
        .unwrap_err()
        .code(),
        CoreErrorCode::InvalidInput
    );
    let mut nested = vec![json!(vec![true; 15]); 64];
    nested[63] = json!(vec![true; 13]);
    validate_scalar_subject(
        &array_definition,
        &json!({"entries":nested}),
        SubjectValidationMode::Complete,
    )
    .unwrap();
    nested[63].as_array_mut().unwrap().push(json!(true));
    assert_eq!(
        validate_scalar_subject(
            &array_definition,
            &json!({"entries":nested}),
            SubjectValidationMode::Complete
        )
        .unwrap_err()
        .code(),
        CoreErrorCode::InvalidInput
    );
    let mut strings = vec!["x".repeat(1024); 64];
    let excess = serde_json::to_vec(&json!({"entries":strings}))
        .unwrap()
        .len()
        - 65536;
    strings[63].truncate(1024 - excess);
    assert_eq!(
        serde_json::to_vec(&json!({"entries":strings}))
            .unwrap()
            .len(),
        65536
    );
    validate_scalar_subject(
        &array_definition,
        &json!({"entries":strings}),
        SubjectValidationMode::Complete,
    )
    .unwrap();
    strings[63].push('x');
    assert_eq!(
        validate_scalar_subject(
            &array_definition,
            &json!({"entries":strings}),
            SubjectValidationMode::Complete
        )
        .unwrap_err()
        .code(),
        CoreErrorCode::InvalidInput
    );
}

#[test]
fn whole_values_reject_null_reserved_keys_and_nonportable_scalars_at_every_level() {
    let definition = one_claim_definition("array", &["credentialSubject", "entries"]);
    validate_scalar_subject(
        &definition,
        &json!({"entries":[{"note":"é".repeat(512)},3.5,false]}),
        SubjectValidationMode::Complete,
    )
    .unwrap();
    for value in [
        json!(null),
        json!({"_sd":["digest"]}),
        json!({"issuer":"override"}),
        json!({"bad.key":true}),
        json!("é".repeat(513)),
        json!(9007199254740992u64),
    ] {
        assert_eq!(
            validate_scalar_subject(
                &definition,
                &json!({"entries":[value]}),
                SubjectValidationMode::Complete
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::InvalidInput
        );
    }
}

#[test]
fn definition_serialized_byte_bound_accepts_the_boundary_and_rejects_one_more_byte() {
    let mut definition = nested_definition_json();
    let claims: Vec<_> = (0..64).map(|index| {
        let name = format!("field{index:02}{}", "x".repeat(57));
        json!({"name":name,"path":["credentialSubject","p".repeat(19),name],"label":"V","value_type":"boolean","required":true})
    }).collect();
    let paths: Vec<_> = claims.iter().map(|claim| claim["path"].clone()).collect();
    definition["claims"] = json!(claims);
    definition["profiles"] = json!(
        (0..16)
            .map(|index| json!({"name":format!("profile_{index}"),"claim_paths":paths}))
            .collect::<Vec<_>>()
    );
    let mut remaining = 131072 - serde_json::to_vec(&definition).unwrap().len();
    for claim in definition["claims"].as_array_mut().unwrap() {
        let added = remaining.min(127);
        claim["label"] = json!("V".repeat(added + 1));
        remaining -= added;
    }
    assert_eq!(remaining, 0);
    let valid: ScalarCredentialDefinition = serde_json::from_value(definition.clone()).unwrap();
    assert_eq!(serde_json::to_vec(&valid).unwrap().len(), 131072);
    validate_scalar_definition(&valid).unwrap();
    let fixture = signed_fixture(valid, json!({}));
    assert!(fixture.authorization.len() <= 262144);
    identity_core::verify_issuer_authorization(
        &fixture.authorization,
        &fixture.anchor,
        &identity_core::IssuerAuthorizationRequest {
            registry_did: "did:web:trust.example".into(),
            credential_issuer_did: "did:web:issuer.example".into(),
            credential_issuer_key_id: "did:web:issuer.example#key-1".into(),
            credential_issuer_public_jwk: fixture.issuer_jwk.clone(),
            definition_id: fixture.definition.id.clone(),
            definition_version: "1".into(),
            credential_type: fixture.definition.credential_type.clone(),
            purpose: None,
        },
        150,
    )
    .unwrap();
    definition["label"] = json!("Structuredx");
    let too_large: ScalarCredentialDefinition = serde_json::from_value(definition).unwrap();
    assert_eq!(serde_json::to_vec(&too_large).unwrap().len(), 131073);
    assert_eq!(
        validate_scalar_definition(&too_large).unwrap_err().code(),
        CoreErrorCode::InvalidInput
    );
}

use identity_core::{
    CoreResult, DisclosureProfile, DisclosureSpec, FixedSaltSource, IssuerAuthorization,
    IssuerAuthorizations, JwsHeader, KeyId, PublicJwk, SdJwtVerificationOptions, Signer,
    TrustListStatus, b64_encode, issue_sd_jwt, present_sd_jwt, public_jwk_sha256_thumbprint,
    sign_compact_jws_json, sign_issuer_authorizations, verify_scalar_credential_authorization,
    verify_sd_jwt_presentation,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
struct TestSigner(SigningKey);
impl Signer for TestSigner {
    fn sign(&self, _: &KeyId, input: &[u8]) -> CoreResult<Vec<u8>> {
        let signature: Signature = self.0.sign(input);
        Ok(signature.to_bytes().to_vec())
    }
}
fn test_signer(byte: u8) -> (TestSigner, PublicJwk) {
    let key = SigningKey::from_slice(&[byte; 32]).unwrap();
    let point = key.verifying_key().to_sec1_point(false);
    let jwk = PublicJwk::p256(
        b64_encode(point.x().unwrap()),
        b64_encode(point.y().unwrap()),
        None,
    );
    (TestSigner(key), jwk)
}
struct SignedFixture {
    definition: ScalarCredentialDefinition,
    authorization: String,
    anchor: PublicJwk,
    issuer: TestSigner,
    issuer_jwk: PublicJwk,
    holder: TestSigner,
    payload: Value,
    header: JwsHeader,
}
fn signed_fixture(definition: ScalarCredentialDefinition, subject: Value) -> SignedFixture {
    let (registry, anchor) = test_signer(1);
    let (issuer, issuer_jwk) = test_signer(2);
    let (holder, holder_jwk) = test_signer(3);
    let document = IssuerAuthorizations {
        version: 1,
        id: "https://trust.example/issuer-authorizations/fixture-374.jwt".into(),
        issuer: "did:web:trust.example".into(),
        iat: 100,
        exp: 200,
        authorizations: vec![IssuerAuthorization {
            credential_issuer_did: "did:web:issuer.example".into(),
            credential_issuer_key_id: "did:web:issuer.example#key-1".into(),
            credential_issuer_public_jwk_sha256_thumbprint: public_jwk_sha256_thumbprint(
                &issuer_jwk,
            )
            .unwrap(),
            definition: definition.clone(),
            status: TrustListStatus::Active,
            key_state: None,
            status_authority: None,
        }],
    };
    let registry_header: JwsHeader = serde_json::from_value(json!({"alg":"ES256","typ":"issuer-authorizations+jwt","kid":"did:web:trust.example#key-1"})).unwrap();
    let authorization = sign_issuer_authorizations(
        &document,
        &registry_header,
        &registry,
        &KeyId::new("registry"),
    )
    .unwrap();
    let payload = json!({
        "@context":["https://www.w3.org/ns/credentials/v2",{"@vocab":"https://example.test/vocab#"}],
        "type":["VerifiableCredential",definition.credential_type],"issuer":"did:web:issuer.example","iss":"did:web:issuer.example",
        "iat":100,"exp":200,"validFrom":"1970-01-01T00:01:40Z","validUntil":"1970-01-01T00:03:20Z",
        "credentialDefinition":{"id":definition.id,"version":definition.version},"credentialSubject":subject,"cnf":{"jwk":holder_jwk},
        "credentialStatus":{"id":"https://issuer.example/status#0","type":"BitstringStatusListEntry","statusPurpose":"revocation","statusListIndex":"0","statusListCredential":"https://issuer.example/status"}
    });
    let header: JwsHeader = serde_json::from_value(
        json!({"alg":"ES256","typ":"vc+sd-jwt","kid":"did:web:issuer.example#key-1"}),
    )
    .unwrap();
    SignedFixture {
        definition,
        authorization,
        anchor,
        issuer,
        issuer_jwk,
        holder,
        payload,
        header,
    }
}
impl SignedFixture {
    fn issue(&self, specs: &[DisclosureSpec]) -> String {
        // Intentional codec seam also constructs adversarial signed issuer data.
        issue_sd_jwt(
            self.payload.clone(),
            specs,
            0,
            &self.header,
            &self.issuer,
            &KeyId::new("issuer"),
            &mut FixedSaltSource::new((1..=specs.len()).map(|index| vec![index as u8; 16])),
        )
        .unwrap()
        .compact
    }
    fn verify(
        &self,
        compact: &str,
        mode: SubjectValidationMode,
    ) -> CoreResult<identity_core::VerifiedSdJwtCredential> {
        verify_scalar_credential_authorization(
            compact,
            &self.issuer_jwk,
            &self.authorization,
            &self.anchor,
            "did:web:trust.example",
            150,
            mode,
        )
    }
    fn specs(&self) -> Vec<DisclosureSpec> {
        self.definition
            .claims
            .iter()
            .map(|claim| {
                let path = claim.full_path();
                DisclosureSpec::new(path[..path.len() - 1].to_vec(), path.last().unwrap())
            })
            .collect()
    }
}
#[test]
fn signed_structured_credential_and_holder_presentation_preserve_exact_values_and_hidden_paths() {
    let fixture = signed_fixture(
        serde_json::from_value(whole_definition_json()).unwrap(),
        whole_subject(),
    );
    validate_scalar_subject(
        &fixture.definition,
        &whole_subject(),
        SubjectValidationMode::Complete,
    )
    .unwrap();
    let compact = fixture.issue(&fixture.specs());
    let received = fixture
        .verify(&compact, SubjectValidationMode::Complete)
        .unwrap();
    assert_eq!(
        received.processed_payload["credentialSubject"]["left"]["name"],
        "North"
    );
    assert_eq!(
        received.processed_payload["credentialSubject"]["right"]["name"],
        "South"
    );
    let profile = DisclosureProfile::new("left_only", [["credentialSubject", "left", "name"]]);
    let presented = present_sd_jwt(
        &compact,
        &profile,
        &fixture.holder,
        &KeyId::new("holder"),
        "https://verifier.example",
        "nonce",
        150,
    )
    .unwrap();
    let verified = verify_sd_jwt_presentation(
        &presented.presentation,
        &fixture.issuer_jwk,
        &SdJwtVerificationOptions::for_profile("https://verifier.example", "nonce", 150, &profile),
    )
    .unwrap();
    assert_eq!(
        verified.processed_payload["credentialSubject"]["left"]["name"],
        "North"
    );
    assert!(
        verified.processed_payload["credentialSubject"]["right"]
            .get("name")
            .is_none()
    );
    fixture
        .verify(
            &presented.disclosed_sd_jwt,
            SubjectValidationMode::Disclosed,
        )
        .unwrap();
    assert_eq!(
        fixture
            .verify(&presented.disclosed_sd_jwt, SubjectValidationMode::Complete)
            .unwrap_err()
            .code(),
        CoreErrorCode::InvalidInput
    );
    let whole = DisclosureProfile::new(
        "whole",
        [
            ["credentialSubject", "details"],
            ["credentialSubject", "entries"],
        ],
    );
    let presented = present_sd_jwt(
        &compact,
        &whole,
        &fixture.holder,
        &KeyId::new("holder"),
        "https://verifier.example",
        "whole-nonce",
        150,
    )
    .unwrap();
    let verified = fixture
        .verify(
            &presented.disclosed_sd_jwt,
            SubjectValidationMode::Disclosed,
        )
        .unwrap();
    assert_eq!(
        verified.processed_payload["credentialSubject"]["details"],
        whole_subject()["details"]
    );
    assert_eq!(
        verified.processed_payload["credentialSubject"]["entries"],
        whole_subject()["entries"]
    );
}

#[test]
fn signed_disclosures_must_name_exact_declared_paths_not_ancestors_or_array_elements() {
    let fixture = signed_fixture(
        serde_json::from_value(nested_definition_json()).unwrap(),
        json!({"left":{"name":"North"},"right":{"name":"South"}}),
    );
    let ancestor = fixture.issue(&[DisclosureSpec::new(["credentialSubject"], "left")]);
    assert_eq!(
        fixture
            .verify(&ancestor, SubjectValidationMode::Complete)
            .unwrap_err()
            .code(),
        CoreErrorCode::TrustCheckFailed
    );
    let fixture = signed_fixture(
        one_claim_definition("array", &["credentialSubject", "entries"]),
        json!({"entries":[]}),
    );
    let disclosure = b64_encode(br#"["array-salt","Secret"]"#);
    let mut payload = fixture.payload.clone();
    payload["credentialSubject"]["entries"] =
        json!([{"...":identity_core::sha256_b64url(disclosure.as_bytes())}]);
    let issuer_jwt = sign_compact_jws_json(
        &fixture.header,
        &payload,
        &fixture.issuer,
        &KeyId::new("issuer"),
    )
    .unwrap();
    let compact = format!("{issuer_jwt}~{disclosure}~");
    assert_eq!(
        fixture
            .verify(&compact, SubjectValidationMode::Complete)
            .unwrap_err()
            .code(),
        CoreErrorCode::TrustCheckFailed
    );
}

#[test]
fn definitions_refuse_aliases_array_traversal_and_definition_wide_overlap() {
    for path in [
        json!([]),
        json!(["credentialSubject", "left", "0"]),
        json!(["credentialSubject", "left", "*"]),
        json!(["credentialSubject", "left.name"]),
        json!(["issuer", "name"]),
        json!(["credentialSubject", "issuer", "name"]),
        json!(["credentialSubject", "left", "other"]),
        json!(["credentialSubject", "left", "name", "extra"]),
    ] {
        let mut definition = nested_definition_json();
        definition["claims"][0]["path"] = path;
        let definition = serde_json::from_value(definition).unwrap();
        assert_eq!(
            validate_scalar_definition(&definition).unwrap_err().code(),
            CoreErrorCode::InvalidInput
        );
    }
    let mut duplicate = nested_definition_json();
    duplicate["claims"][1]["path"] = duplicate["claims"][0]["path"].clone();
    let mut overlap = nested_definition_json();
    overlap["claims"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name":"left","label":"Left","value_type":"object","required":false}));
    overlap["profiles"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name":"separate","claim_paths":[["credentialSubject","left"]]}));
    for definition in [duplicate, overlap] {
        assert_eq!(
            validate_scalar_definition(&serde_json::from_value(definition).unwrap())
                .unwrap_err()
                .code(),
            CoreErrorCode::InvalidInput
        );
    }
    let mut definition = nested_definition_json();
    definition["profiles"][0]["claim_paths"] = json!([["credentialSubject", "name"]]);
    assert_eq!(
        validate_scalar_definition(&serde_json::from_value(definition).unwrap())
            .unwrap_err()
            .code(),
        CoreErrorCode::InvalidInput
    );
}
#[test]
fn scalar_serialization_stays_identical_and_unknown_definition_shapes_are_not_extensions() {
    let scalar: Value = serde_json::from_str(include_str!(
        "../../../vectors/conformance/scalar-definitions.json"
    ))
    .unwrap();
    let definition: ScalarCredentialDefinition =
        serde_json::from_value(scalar["definition"].clone()).unwrap();
    assert_eq!(
        serde_json::to_value(&definition).unwrap(),
        scalar["definition"]
    );
    assert!(definition.claims.iter().all(|claim| claim.path.is_none()));
    for change in [
        json!({"path":null}),
        json!({"path":["credentialSubject",0]}),
        json!({"properties":{}}),
        json!({"items":{}}),
        json!({"value_type":"date"}),
    ] {
        let mut definition = whole_definition_json();
        definition["claims"][0]
            .as_object_mut()
            .unwrap()
            .extend(change.as_object().unwrap().clone());
        assert!(serde_json::from_value::<ScalarCredentialDefinition>(definition).is_err());
    }
}
#[test]
fn signed_whole_values_cannot_hide_partial_descendants_or_reserved_sd_machinery() {
    let fixture = signed_fixture(
        serde_json::from_value(whole_definition_json()).unwrap(),
        whole_subject(),
    );
    let partial = fixture.issue(&[DisclosureSpec::new(
        ["credentialSubject", "details"],
        "count",
    )]);
    assert_eq!(
        fixture
            .verify(&partial, SubjectValidationMode::Complete)
            .unwrap_err()
            .code(),
        CoreErrorCode::TrustCheckFailed
    );
    let mut payload = fixture.payload.clone();
    payload["credentialSubject"]["details"]["_sd"] = json!([]);
    let signed = sign_compact_jws_json(
        &fixture.header,
        &payload,
        &fixture.issuer,
        &KeyId::new("issuer"),
    )
    .unwrap();
    assert_eq!(
        fixture
            .verify(&format!("{signed}~"), SubjectValidationMode::Complete)
            .unwrap_err()
            .code(),
        CoreErrorCode::InvalidInput
    );
    let mut payload = fixture.payload.clone();
    payload["credentialSubject"]["entries"] =
        json!([{"...":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]);
    let signed = sign_compact_jws_json(
        &fixture.header,
        &payload,
        &fixture.issuer,
        &KeyId::new("issuer"),
    )
    .unwrap();
    assert_eq!(
        fixture
            .verify(&format!("{signed}~"), SubjectValidationMode::Complete)
            .unwrap_err()
            .code(),
        CoreErrorCode::InvalidInput
    );
}

#[test]
fn rust_verifies_the_node_signed_portable_structured_vector_and_refusal_codes() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../vectors/conformance/structured-definitions.json"
    ))
    .unwrap();
    let definition: ScalarCredentialDefinition =
        serde_json::from_value(fixture["definition"].clone()).unwrap();
    let issuer = serde_json::from_value(fixture["issuer_jwk"].clone()).unwrap();
    let anchor = serde_json::from_value(fixture["anchor"].clone()).unwrap();
    let verify = |token: &str, mode| {
        verify_scalar_credential_authorization(
            token,
            &issuer,
            fixture["compact_authorization"].as_str().unwrap(),
            &anchor,
            "did:web:trust.example",
            150,
            mode,
        )
    };
    validate_scalar_subject(
        &definition,
        &fixture["subject"],
        SubjectValidationMode::Complete,
    )
    .unwrap();
    let result = verify(
        fixture["compact_credential"].as_str().unwrap(),
        SubjectValidationMode::Complete,
    )
    .unwrap();
    assert_eq!(
        result.processed_payload["credentialSubject"]["left"]["name"],
        "North"
    );
    assert_eq!(
        result.processed_payload["credentialSubject"]["right"]["name"],
        "South"
    );
    assert_eq!(
        result.processed_payload["credentialSubject"]["details"],
        fixture["subject"]["details"]
    );
    assert_eq!(
        result.processed_payload["credentialSubject"]["entries"],
        fixture["subject"]["entries"]
    );
    for row in fixture["presentations"].as_array().unwrap() {
        let profile: DisclosureProfile = serde_json::from_value(row["profile"].clone()).unwrap();
        verify_sd_jwt_presentation(
            row["presentation"].as_str().unwrap(),
            &issuer,
            &SdJwtVerificationOptions::for_profile(
                "https://verifier.example",
                row["nonce"].as_str().unwrap(),
                150,
                &profile,
            ),
        )
        .unwrap();
        let token = row["disclosed_credential"].as_str().unwrap();
        let subject = verify(token, SubjectValidationMode::Disclosed)
            .unwrap()
            .processed_payload["credentialSubject"]
            .clone();
        if profile.name == "left_only" {
            assert_eq!(subject["left"]["name"], "North");
            assert!(subject["right"].get("name").is_none());
            assert!(subject.get("details").is_none());
        } else {
            assert_eq!(subject["details"], fixture["subject"]["details"]);
            assert_eq!(subject["entries"], fixture["subject"]["entries"]);
            assert!(subject["left"].get("name").is_none());
            assert!(subject["right"].get("name").is_none());
        }
        assert_eq!(
            verify(token, SubjectValidationMode::Complete)
                .unwrap_err()
                .code(),
            CoreErrorCode::InvalidInput
        );
    }
    for key in [
        "overlapping_credential",
        "ancestor_credential",
        "partial_whole_credential",
        "array_element_credential",
    ] {
        assert_eq!(
            verify(
                fixture[key].as_str().unwrap(),
                SubjectValidationMode::Complete
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::TrustCheckFailed
        );
    }
    for subject in fixture["invalid_subjects"].as_array().unwrap() {
        assert_eq!(
            validate_scalar_subject(&definition, subject, SubjectValidationMode::Complete)
                .unwrap_err()
                .code(),
            CoreErrorCode::InvalidInput
        );
    }
    for definition in fixture["invalid_definitions"].as_array().unwrap() {
        assert_eq!(
            validate_scalar_definition(&serde_json::from_value(definition.clone()).unwrap())
                .unwrap_err()
                .code(),
            CoreErrorCode::InvalidInput
        );
    }
    for definition in fixture["malformed_definitions"].as_array().unwrap() {
        assert!(serde_json::from_value::<ScalarCredentialDefinition>(definition.clone()).is_err());
    }
}
