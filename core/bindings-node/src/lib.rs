//! Node napi-rs binding for `identity-core`.
//!
//! The exported functions marshal JSON strings and opaque key handles. TypeScript
//! owns ergonomics only; signing and verification stay inside Rust.

mod persistent_signer;
mod scalar_definitions;
mod scoped_permissions;

use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

#[cfg(not(feature = "partner-runtime"))]
use identity_core::deterministic_test_x509_identity;
use identity_core::{
    BitstringStatusListCredentialPayload, ClientAttestationVerificationOptions, CoreError,
    CoreErrorCode, CoreResult, CredentialFormat, CredentialStatus, DisclosureProfile,
    DisclosureSpec, DpopVerificationOptions, FixedSaltSource, HttpResolver, JwePublicJwk,
    JwsHeader, KeyId, Oid4vciCredentialResponseEncryption, PublicJwk,
    SdJwtCredentialVerificationOptions, SdJwtIssueOptions, Signer, TrustListPayload, b64_decode,
    b64_encode, build_did_web_document, crate_name, create_oid4vci_client_attestation,
    create_oid4vci_client_attestation_pop, create_oid4vci_dpop_proof, create_oid4vci_holder_proof,
    decrypt_oid4vci_jwe, did_web_from_host, did_web_to_https_url, encode_bitstring_status_list,
    encrypt_oid4vci_credential_response, encrypt_oid4vci_jwe, issue_sd_jwt as core_issue_sd_jwt,
    issue_sd_jwt_with_format, planned_issuer_did_web_identities, present_sd_jwt,
    public_jwk_sha256_thumbprint, random_p256_secret, random_urlsafe, resolve_credential_status,
    resolve_credential_status_at, resolve_did_web_document, resolve_did_web_key, sha256_b64url,
    sign_bitstring_status_list_credential, sign_compact_jws_json, sign_trust_list,
    status_list_size_report, validate_oid4vci_credential_response_encryption, verify_attachment,
    verify_bitstring_status_list_credential, verify_bitstring_status_list_credential_at,
    verify_client_attestation, verify_compact_jws_json, verify_compact_jws_with_did_web_issuer,
    verify_credential_status_active, verify_credential_status_active_at, verify_dpop_proof,
    verify_oid4vp_request_object, verify_sd_jwt_credential, verify_sd_jwt_presentation,
    verify_sd_jwt_presentation_with_did_web, verify_trust_list, verify_trust_list_accreditation,
    verify_verifier_trust_list_accreditation,
};

use napi::{Error as NapiError, Result as NapiResult, Status};
use napi_derive::napi;
use p256::{
    SecretKey,
    ecdsa::{Signature, SigningKey, signature::Signer as _},
};
use serde_json::Value;

static SOFTWARE_KEYS: OnceLock<Mutex<HashMap<String, SigningKey>>> = OnceLock::new();

#[cfg(not(feature = "partner-runtime"))]
const TEST_ISSUER_PRIVATE_SCALAR: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
#[cfg(not(feature = "partner-runtime"))]
const TEST_HOLDER_PRIVATE_SCALAR: [u8; 32] = [
    0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10,
    0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x01,
];

struct NodeSoftwareSigner;

impl Signer for NodeSoftwareSigner {
    fn sign(&self, key_id: &KeyId, signing_input: &[u8]) -> CoreResult<Vec<u8>> {
        if let Some(signature) = persistent_signer::sign(key_id, signing_input)? {
            return Ok(signature);
        }
        let keys = software_keys().lock().map_err(|_| {
            CoreError::new(
                CoreErrorCode::SigningFailed,
                "node software key store lock is poisoned",
            )
        })?;
        let signing_key = keys.get(key_id.as_str()).ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::KeyNotFound,
                format!("node software key not found: {}", key_id.as_str()),
            )
        })?;
        let signature: Signature = signing_key.sign(signing_input);
        Ok(signature.to_bytes().to_vec())
    }
}

#[derive(Clone, Debug)]
struct JsonMapResolver {
    responses: HashMap<String, Vec<u8>>,
}

impl HttpResolver for JsonMapResolver {
    fn resolve(&self, url: &str) -> CoreResult<Vec<u8>> {
        self.responses.get(url).cloned().ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::ResolverUnavailable,
                format!("node resolver has no response for {url}"),
            )
        })
    }
}

#[napi(js_name = "crateName")]
pub fn crate_name_raw() -> &'static str {
    crate_name()
}

#[cfg(not(feature = "partner-runtime"))]
#[napi(js_name = "installDeterministicTestKeyRaw")]
pub fn install_deterministic_test_key_raw(key_id: String, slot: String) -> NapiResult<String> {
    let scalar = match slot.as_str() {
        "issuer" => TEST_ISSUER_PRIVATE_SCALAR,
        "holder" => TEST_HOLDER_PRIVATE_SCALAR,
        slot if slot.starts_with("issuer:") => deterministic_issuer_scalar(slot)?,
        _ => {
            return Err(NapiError::new(
                Status::InvalidArg,
                "slot must be issuer, holder, or issuer:<0-254>",
            ));
        }
    };
    let signing_key = SigningKey::from_slice(&scalar)
        .map_err(|_| NapiError::new(Status::InvalidArg, "deterministic test scalar is invalid"))?;
    insert_key(key_id.clone(), signing_key)?;
    serialize(&public_jwk_for_key_id(&key_id).map_err(to_napi_error)?)
}

#[cfg(not(feature = "partner-runtime"))]
#[napi(js_name = "installDeterministicTestX509KeyRaw")]
pub fn install_deterministic_test_x509_key_raw(key_id: String, slot: String) -> NapiResult<String> {
    let identity = deterministic_test_x509_identity(&key_id, &slot).map_err(to_napi_error)?;
    let scalar = deterministic_issuer_scalar(&slot)?;
    let signing_key = SigningKey::from_slice(&scalar)
        .map_err(|_| NapiError::new(Status::InvalidArg, "deterministic test scalar is invalid"))?;
    insert_key(key_id, signing_key)?;
    serialize(&identity)
}

#[cfg(not(feature = "partner-runtime"))]
fn deterministic_issuer_scalar(slot: &str) -> NapiResult<[u8; 32]> {
    let index = slot
        .strip_prefix("issuer:")
        .and_then(|value| value.parse::<u8>().ok())
        .ok_or_else(|| NapiError::new(Status::InvalidArg, "issuer slot must be issuer:<0-254>"))?;
    if index == u8::MAX {
        return Err(NapiError::new(
            Status::InvalidArg,
            "issuer slot index must be lower than 255",
        ));
    }

    let mut scalar = [0_u8; 32];
    scalar[31] = index + 1;
    Ok(scalar)
}

#[napi(js_name = "publicJwkRaw")]
pub fn public_jwk_raw(key_id: String) -> NapiResult<String> {
    serialize(&public_jwk_for_key_id(&key_id).map_err(to_napi_error)?)
}

#[napi(js_name = "sha256B64UrlRaw")]
pub fn sha256_b64url_raw(input_base64url: String) -> NapiResult<String> {
    let input = b64_decode(&input_base64url).map_err(to_napi_error)?;
    Ok(sha256_b64url(&input))
}

#[napi(js_name = "randomUrlsafeRaw")]
pub fn random_urlsafe_raw(byte_length: u32) -> NapiResult<String> {
    random_urlsafe(byte_length as usize).map_err(to_napi_error)
}

#[napi(js_name = "generateOidfEncryptionKeyRaw")]
pub fn generate_oidf_encryption_key_raw(key_id: String) -> NapiResult<String> {
    let secret = random_p256_secret().map_err(to_napi_error)?;
    let public = JwePublicJwk::from_public_key(
        secret.public_key(),
        Some(key_id.clone()),
        Some("ECDH-ES".to_owned()),
    );
    insert_key(key_id, SigningKey::from(secret))?;
    serialize(&public)
}

#[napi(js_name = "encryptOid4vciJweRaw")]
pub fn encrypt_oid4vci_jwe_raw(
    plaintext_json: String,
    parameters_json: String,
) -> NapiResult<String> {
    let plaintext: Value = parse(&plaintext_json)?;
    let parameters: Oid4vciCredentialResponseEncryption = parse(&parameters_json)?;
    encrypt_oid4vci_jwe(&plaintext, &parameters).map_err(to_napi_error)
}

#[napi(js_name = "signCompactJwsJsonRaw")]
pub fn sign_compact_jws_json_raw(
    header_json: String,
    payload_json: String,
    key_id: String,
) -> NapiResult<String> {
    let header: JwsHeader = parse(&header_json)?;
    let payload: Value = parse(&payload_json)?;
    sign_compact_jws_json(&header, &payload, &NodeSoftwareSigner, &KeyId::new(key_id))
        .map_err(to_napi_error)
}

#[napi(js_name = "createOid4vciHolderProofRaw")]
pub fn create_oid4vci_holder_proof_raw(
    audience: String,
    nonce: String,
    iat: i64,
    public_jwk_json: String,
    key_id: String,
) -> NapiResult<String> {
    let public_jwk: PublicJwk = parse(&public_jwk_json)?;
    create_oid4vci_holder_proof(
        &audience,
        &nonce,
        iat,
        &public_jwk,
        &NodeSoftwareSigner,
        &KeyId::new(key_id),
    )
    .map_err(to_napi_error)
}

#[napi(js_name = "createOid4vciDpopProofRaw")]
#[allow(clippy::too_many_arguments)]
pub fn create_oid4vci_dpop_proof_raw(
    method: String,
    target_uri: String,
    iat: i64,
    jti: String,
    nonce: Option<String>,
    access_token: Option<String>,
    public_jwk_json: String,
    key_id: String,
) -> NapiResult<String> {
    let public_jwk: PublicJwk = parse(&public_jwk_json)?;
    create_oid4vci_dpop_proof(
        &method,
        &target_uri,
        iat,
        &jti,
        nonce.as_deref(),
        access_token.as_deref(),
        &public_jwk,
        &NodeSoftwareSigner,
        &KeyId::new(key_id),
    )
    .map_err(to_napi_error)
}

#[napi(js_name = "createOid4vciClientAttestationRaw")]
#[allow(clippy::too_many_arguments)]
pub fn create_oid4vci_client_attestation_raw(
    attester_issuer: String,
    client_id: String,
    iat: i64,
    x5c_json: String,
    instance_public_jwk_json: String,
    attester_public_jwk_json: String,
    key_id: String,
) -> NapiResult<String> {
    let x5c: Vec<String> = parse(&x5c_json)?;
    let instance_public_jwk: PublicJwk = parse(&instance_public_jwk_json)?;
    let attester_public_jwk: PublicJwk = parse(&attester_public_jwk_json)?;
    create_oid4vci_client_attestation(
        &attester_issuer,
        &client_id,
        iat,
        &x5c,
        &instance_public_jwk,
        &attester_public_jwk,
        &NodeSoftwareSigner,
        &KeyId::new(key_id),
    )
    .map_err(to_napi_error)
}

#[napi(js_name = "createOid4vciClientAttestationPopRaw")]
#[allow(clippy::too_many_arguments)]
pub fn create_oid4vci_client_attestation_pop_raw(
    client_id: String,
    audience: String,
    iat: i64,
    jti: String,
    challenge: Option<String>,
    instance_public_jwk_json: String,
    key_id: String,
) -> NapiResult<String> {
    let instance_public_jwk: PublicJwk = parse(&instance_public_jwk_json)?;
    create_oid4vci_client_attestation_pop(
        &client_id,
        &audience,
        iat,
        &jti,
        challenge.as_deref(),
        &instance_public_jwk,
        &NodeSoftwareSigner,
        &KeyId::new(key_id),
    )
    .map_err(to_napi_error)
}

#[napi(js_name = "verifyCompactJwsJsonRaw")]
pub fn verify_compact_jws_json_raw(
    compact_jws: String,
    public_jwk_json: String,
) -> NapiResult<String> {
    let public_jwk: PublicJwk = parse(&public_jwk_json)?;
    let (header, payload): (JwsHeader, Value) =
        verify_compact_jws_json(&compact_jws, &public_jwk).map_err(to_napi_error)?;
    serialize(&serde_json::json!({
        "header": header,
        "payload": payload,
    }))
}

#[napi(js_name = "verifyDpopProofRaw")]
pub fn verify_dpop_proof_raw(compact_jws: String, options_json: String) -> NapiResult<String> {
    let options: DpopVerificationOptions = parse(&options_json)?;
    let verified = verify_dpop_proof(&compact_jws, &options).map_err(to_napi_error)?;
    serialize(&verified)
}

#[napi(js_name = "verifyClientAttestationRaw")]
pub fn verify_client_attestation_raw(
    client_attestation_jwt: String,
    client_attestation_pop_jwt: String,
    options_json: String,
) -> NapiResult<String> {
    let options: ClientAttestationVerificationOptions = parse(&options_json)?;
    let verified = verify_client_attestation(
        &client_attestation_jwt,
        &client_attestation_pop_jwt,
        &options,
    )
    .map_err(to_napi_error)?;
    serialize(&verified)
}

#[napi(js_name = "oid4vciEncryptionPublicJwkRaw")]
pub fn oid4vci_encryption_public_jwk_raw(key_id: String) -> NapiResult<String> {
    serialize(&jwe_public_jwk_for_key_id(&key_id).map_err(to_napi_error)?)
}

#[napi(js_name = "encryptOid4vciCredentialResponseRaw")]
pub fn encrypt_oid4vci_credential_response_raw(
    plaintext_json: String,
    parameters_json: String,
) -> NapiResult<String> {
    let plaintext: Value = parse(&plaintext_json)?;
    let parameters: Oid4vciCredentialResponseEncryption = parse(&parameters_json)?;
    encrypt_oid4vci_credential_response(&plaintext, &parameters).map_err(to_napi_error)
}

#[napi(js_name = "validateOid4vciCredentialResponseEncryptionRaw")]
pub fn validate_oid4vci_credential_response_encryption_raw(
    parameters_json: String,
) -> NapiResult<String> {
    let parameters: Oid4vciCredentialResponseEncryption = parse(&parameters_json)?;
    validate_oid4vci_credential_response_encryption(&parameters).map_err(to_napi_error)?;
    Ok("ok".to_owned())
}

#[napi(js_name = "decryptOid4vciJweRaw")]
pub fn decrypt_oid4vci_jwe_raw(compact_jwe: String, key_id: String) -> NapiResult<String> {
    let recipient_secret = secret_key_for_key_id(&key_id).map_err(to_napi_error)?;
    let plaintext = decrypt_oid4vci_jwe(&compact_jwe, &recipient_secret, Some(&key_id))
        .map_err(to_napi_error)?;
    serialize(&plaintext)
}

#[napi(js_name = "issueSdJwtRaw")]
pub fn issue_sd_jwt_raw(
    payload_json: String,
    disclosure_specs_json: String,
    decoy_digests: u32,
    header_json: String,
    key_id: String,
    salts_json: String,
) -> NapiResult<String> {
    let payload: Value = parse(&payload_json)?;
    let disclosure_specs: Vec<DisclosureSpec> = parse(&disclosure_specs_json)?;
    let header: JwsHeader = parse(&header_json)?;
    let mut salt_source = fixed_salt_source_from_json(&salts_json)?;
    let issued = core_issue_sd_jwt(
        payload,
        &disclosure_specs,
        decoy_digests as usize,
        &header,
        &NodeSoftwareSigner,
        &KeyId::new(key_id),
        &mut salt_source,
    )
    .map_err(to_napi_error)?;
    serialize(&issued)
}

#[napi(js_name = "issueSdJwtWithFormatRaw")]
pub fn issue_sd_jwt_with_format_raw(
    payload_json: String,
    disclosure_specs_json: String,
    decoy_digests: u32,
    header_json: String,
    key_id: String,
    salts_json: String,
    format_json: String,
) -> NapiResult<String> {
    let payload: Value = parse(&payload_json)?;
    let disclosure_specs: Vec<DisclosureSpec> = parse(&disclosure_specs_json)?;
    let header: JwsHeader = parse(&header_json)?;
    let format: CredentialFormat = parse(&format_json)?;
    let mut salt_source = fixed_salt_source_from_json(&salts_json)?;
    let issued = issue_sd_jwt_with_format(
        payload,
        &disclosure_specs,
        &header,
        &NodeSoftwareSigner,
        &KeyId::new(key_id),
        &mut salt_source,
        SdJwtIssueOptions {
            decoy_digests: decoy_digests as usize,
            format,
        },
    )
    .map_err(to_napi_error)?;
    serialize(&issued)
}

#[napi(js_name = "presentSdJwtRaw")]
pub fn present_sd_jwt_raw(
    compact_sd_jwt: String,
    profile_json: String,
    holder_key_id: String,
    audience: String,
    nonce: String,
    iat: i64,
) -> NapiResult<String> {
    let profile: DisclosureProfile = parse(&profile_json)?;
    let presentation = present_sd_jwt(
        &compact_sd_jwt,
        &profile,
        &NodeSoftwareSigner,
        &KeyId::new(holder_key_id),
        audience,
        nonce,
        iat,
    )
    .map_err(to_napi_error)?;
    serialize(&presentation)
}

#[napi(js_name = "verifySdJwtPresentationRaw")]
pub fn verify_sd_jwt_presentation_raw(
    presentation: String,
    issuer_jwk_json: String,
    options_json: String,
) -> NapiResult<String> {
    let issuer_jwk: PublicJwk = parse(&issuer_jwk_json)?;
    let options = parse(&options_json)?;
    let verified =
        verify_sd_jwt_presentation(&presentation, &issuer_jwk, &options).map_err(to_napi_error)?;
    serialize(&verified)
}

#[napi(js_name = "verifySdJwtCredentialRaw")]
pub fn verify_sd_jwt_credential_raw(
    compact_sd_jwt: String,
    issuer_jwk_json: String,
    options_json: String,
) -> NapiResult<String> {
    let issuer_jwk: PublicJwk = parse(&issuer_jwk_json)?;
    let options: SdJwtCredentialVerificationOptions = parse(&options_json)?;
    let verified =
        verify_sd_jwt_credential(&compact_sd_jwt, &issuer_jwk, &options).map_err(to_napi_error)?;
    serialize(&verified)
}

#[napi(js_name = "verifySdJwtPresentationWithDidWebRaw")]
pub fn verify_sd_jwt_presentation_with_did_web_raw(
    presentation: String,
    resolver_responses_json: String,
    options_json: String,
) -> NapiResult<String> {
    let resolver = resolver_from_json(&resolver_responses_json)?;
    let options = parse(&options_json)?;
    let verified = verify_sd_jwt_presentation_with_did_web(&presentation, &resolver, &options)
        .map_err(to_napi_error)?;
    serialize(&verified)
}

#[napi(js_name = "verifyCompactJwsWithDidWebIssuerRaw")]
pub fn verify_compact_jws_with_did_web_issuer_raw(
    compact_jws: String,
    resolver_responses_json: String,
) -> NapiResult<String> {
    let resolver = resolver_from_json(&resolver_responses_json)?;
    serialize(
        &verify_compact_jws_with_did_web_issuer(&compact_jws, &resolver).map_err(to_napi_error)?,
    )
}

#[napi(js_name = "verifyOid4vpRequestObjectRaw")]
pub fn verify_oid4vp_request_object_raw(
    compact_jws: String,
    resolver_responses_json: String,
    now_unix_seconds: i64,
) -> NapiResult<String> {
    let resolver = resolver_from_json(&resolver_responses_json)?;
    serialize(
        &verify_oid4vp_request_object(&compact_jws, &resolver, now_unix_seconds)
            .map_err(to_napi_error)?,
    )
}

#[napi(js_name = "didWebFromHostRaw")]
pub fn did_web_from_host_raw(host: String) -> NapiResult<String> {
    did_web_from_host(&host).map_err(to_napi_error)
}

#[napi(js_name = "didWebToHttpsUrlRaw")]
pub fn did_web_to_https_url_raw(did: String) -> NapiResult<String> {
    did_web_to_https_url(&did).map_err(to_napi_error)
}

#[napi(js_name = "plannedIssuerDidWebIdentitiesRaw")]
pub fn planned_issuer_did_web_identities_raw(base_domain: String) -> NapiResult<String> {
    serialize(&planned_issuer_did_web_identities(&base_domain).map_err(to_napi_error)?)
}

#[napi(js_name = "buildDidWebDocumentRaw")]
pub fn build_did_web_document_raw(did: String, public_jwks_json: String) -> NapiResult<String> {
    let public_jwks: Vec<PublicJwk> = parse(&public_jwks_json)?;
    serialize(&build_did_web_document(&did, &public_jwks).map_err(to_napi_error)?)
}

#[napi(js_name = "resolveDidWebDocumentRaw")]
pub fn resolve_did_web_document_raw(
    did: String,
    resolver_responses_json: String,
) -> NapiResult<String> {
    let resolver = resolver_from_json(&resolver_responses_json)?;
    serialize(&resolve_did_web_document(&did, &resolver).map_err(to_napi_error)?)
}

#[napi(js_name = "resolveDidWebKeyRaw")]
pub fn resolve_did_web_key_raw(
    issuer_did: String,
    kid: String,
    resolver_responses_json: String,
) -> NapiResult<String> {
    let resolver = resolver_from_json(&resolver_responses_json)?;
    serialize(&resolve_did_web_key(&issuer_did, &kid, &resolver).map_err(to_napi_error)?)
}

#[napi(js_name = "encodeBitstringStatusListRaw")]
pub fn encode_bitstring_status_list_raw(
    bit_len: u32,
    set_indices_json: String,
) -> NapiResult<String> {
    let set_indices: Vec<usize> = parse(&set_indices_json)?;
    encode_bitstring_status_list(bit_len as usize, &set_indices).map_err(to_napi_error)
}

#[napi(js_name = "statusListSizeReportRaw")]
pub fn status_list_size_report_raw(bit_len: u32, encoded_list: String) -> NapiResult<String> {
    serialize(&status_list_size_report(bit_len as usize, &encoded_list).map_err(to_napi_error)?)
}

#[napi(js_name = "publicJwkSha256ThumbprintRaw")]
pub fn public_jwk_sha256_thumbprint_raw(public_jwk_json: String) -> NapiResult<String> {
    let public_jwk: PublicJwk = parse(&public_jwk_json)?;
    public_jwk_sha256_thumbprint(&public_jwk).map_err(to_napi_error)
}

#[napi(js_name = "signTrustListRaw")]
pub fn sign_trust_list_raw(
    payload_json: String,
    header_json: String,
    key_id: String,
) -> NapiResult<String> {
    let payload: TrustListPayload = parse(&payload_json)?;
    let header: JwsHeader = parse(&header_json)?;
    sign_trust_list(&payload, &header, &NodeSoftwareSigner, &KeyId::new(key_id))
        .map_err(to_napi_error)
}

#[napi(js_name = "verifyTrustListRaw")]
pub fn verify_trust_list_raw(
    compact_jws: String,
    trust_anchor_jwk_json: String,
) -> NapiResult<String> {
    let trust_anchor_jwk: PublicJwk = parse(&trust_anchor_jwk_json)?;
    serialize(&verify_trust_list(&compact_jws, &trust_anchor_jwk).map_err(to_napi_error)?)
}

#[napi(js_name = "verifyTrustListAccreditationRaw")]
pub fn verify_trust_list_accreditation_raw(
    compact_jws: String,
    trust_anchor_jwk_json: String,
    issuer_did: String,
    credential_type: String,
    issuer_jwk_json: String,
    now_unix_seconds: i64,
) -> NapiResult<String> {
    let trust_anchor_jwk: PublicJwk = parse(&trust_anchor_jwk_json)?;
    let issuer_jwk: PublicJwk = parse(&issuer_jwk_json)?;
    serialize(
        &verify_trust_list_accreditation(
            &compact_jws,
            &trust_anchor_jwk,
            &issuer_did,
            &credential_type,
            &issuer_jwk,
            now_unix_seconds,
        )
        .map_err(to_napi_error)?,
    )
}

#[napi(js_name = "verifyVerifierTrustListAccreditationRaw")]
pub fn verify_verifier_trust_list_accreditation_raw(
    compact_jws: String,
    trust_anchor_jwk_json: String,
    verifier_did: String,
    credential_type: String,
    profile_name: String,
    requested_claim_paths_json: String,
    now_unix_seconds: i64,
) -> NapiResult<String> {
    let trust_anchor_jwk: PublicJwk = parse(&trust_anchor_jwk_json)?;
    let requested_claim_paths: Vec<Vec<String>> = parse(&requested_claim_paths_json)?;
    serialize(
        &verify_verifier_trust_list_accreditation(
            &compact_jws,
            &trust_anchor_jwk,
            &verifier_did,
            &credential_type,
            &profile_name,
            &requested_claim_paths,
            now_unix_seconds,
        )
        .map_err(to_napi_error)?,
    )
}

#[napi(js_name = "signBitstringStatusListCredentialRaw")]
pub fn sign_bitstring_status_list_credential_raw(
    payload_json: String,
    header_json: String,
    key_id: String,
) -> NapiResult<String> {
    let payload: BitstringStatusListCredentialPayload = parse(&payload_json)?;
    let header: JwsHeader = parse(&header_json)?;
    sign_bitstring_status_list_credential(
        &payload,
        &header,
        &NodeSoftwareSigner,
        &KeyId::new(key_id),
    )
    .map_err(to_napi_error)
}

#[napi(js_name = "verifyBitstringStatusListCredentialRaw")]
pub fn verify_bitstring_status_list_credential_raw(
    compact_jws: String,
    status_list_jwk_json: String,
) -> NapiResult<String> {
    let status_list_jwk: PublicJwk = parse(&status_list_jwk_json)?;
    serialize(
        &verify_bitstring_status_list_credential(&compact_jws, &status_list_jwk)
            .map_err(to_napi_error)?,
    )
}

#[napi(js_name = "verifyBitstringStatusListCredentialAtRaw")]
pub fn verify_bitstring_status_list_credential_at_raw(
    compact_jws: String,
    status_list_jwk_json: String,
    now_unix_seconds: i64,
) -> NapiResult<String> {
    let status_list_jwk: PublicJwk = parse(&status_list_jwk_json)?;
    serialize(
        &verify_bitstring_status_list_credential_at(
            &compact_jws,
            &status_list_jwk,
            now_unix_seconds,
        )
        .map_err(to_napi_error)?,
    )
}

#[napi(js_name = "resolveCredentialStatusRaw")]
pub fn resolve_credential_status_raw(
    status_json: String,
    resolver_responses_json: String,
    status_list_jwk_json: String,
) -> NapiResult<String> {
    let status: CredentialStatus = parse(&status_json)?;
    let resolver = resolver_from_json(&resolver_responses_json)?;
    let status_list_jwk: PublicJwk = parse(&status_list_jwk_json)?;
    serialize(
        &resolve_credential_status(&status, &resolver, &status_list_jwk).map_err(to_napi_error)?,
    )
}

#[napi(js_name = "resolveCredentialStatusAtRaw")]
pub fn resolve_credential_status_at_raw(
    status_json: String,
    resolver_responses_json: String,
    status_list_jwk_json: String,
    now_unix_seconds: i64,
) -> NapiResult<String> {
    let status: CredentialStatus = parse(&status_json)?;
    let resolver = resolver_from_json(&resolver_responses_json)?;
    let status_list_jwk: PublicJwk = parse(&status_list_jwk_json)?;
    serialize(
        &resolve_credential_status_at(&status, &resolver, &status_list_jwk, now_unix_seconds)
            .map_err(to_napi_error)?,
    )
}

#[napi(js_name = "verifyCredentialStatusActiveRaw")]
pub fn verify_credential_status_active_raw(
    status_json: String,
    resolver_responses_json: String,
    status_list_jwk_json: String,
) -> NapiResult<String> {
    let status: CredentialStatus = parse(&status_json)?;
    let resolver = resolver_from_json(&resolver_responses_json)?;
    let status_list_jwk: PublicJwk = parse(&status_list_jwk_json)?;
    verify_credential_status_active(&status, &resolver, &status_list_jwk).map_err(to_napi_error)?;
    Ok("ok".to_owned())
}

#[napi(js_name = "verifyCredentialStatusActiveAtRaw")]
pub fn verify_credential_status_active_at_raw(
    status_json: String,
    resolver_responses_json: String,
    status_list_jwk_json: String,
    now_unix_seconds: i64,
) -> NapiResult<String> {
    let status: CredentialStatus = parse(&status_json)?;
    let resolver = resolver_from_json(&resolver_responses_json)?;
    let status_list_jwk: PublicJwk = parse(&status_list_jwk_json)?;
    verify_credential_status_active_at(&status, &resolver, &status_list_jwk, now_unix_seconds)
        .map_err(to_napi_error)?;
    Ok("ok".to_owned())
}

#[napi(js_name = "verifyAttachmentRaw")]
pub fn verify_attachment_raw(
    attachment_base64url: String,
    expected_sha256_b64url: String,
) -> NapiResult<String> {
    let attachment = b64_decode(&attachment_base64url).map_err(to_napi_error)?;
    verify_attachment(&attachment, &expected_sha256_b64url).map_err(to_napi_error)?;
    Ok("ok".to_owned())
}

fn software_keys() -> &'static Mutex<HashMap<String, SigningKey>> {
    SOFTWARE_KEYS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn insert_key(key_id: String, signing_key: SigningKey) -> NapiResult<()> {
    software_keys()
        .lock()
        .map_err(|_| {
            NapiError::new(
                Status::GenericFailure,
                "node software key store lock failed",
            )
        })?
        .insert(key_id, signing_key);
    Ok(())
}

fn public_jwk_for_key_id(key_id: &str) -> CoreResult<PublicJwk> {
    if let Some(public) = persistent_signer::public_jwk(key_id)? {
        return Ok(public);
    }
    let keys = software_keys().lock().map_err(|_| {
        CoreError::new(
            CoreErrorCode::KeyNotFound,
            "node software key store lock failed",
        )
    })?;
    let signing_key = keys.get(key_id).ok_or_else(|| {
        CoreError::new(
            CoreErrorCode::KeyNotFound,
            format!("node software key not found: {key_id}"),
        )
    })?;
    Ok(public_jwk_from_signing_key(
        signing_key,
        Some(key_id.to_owned()),
    ))
}

fn secret_key_for_key_id(key_id: &str) -> CoreResult<SecretKey> {
    let signing_key = software_keys()
        .lock()
        .map_err(|_| {
            CoreError::new(
                CoreErrorCode::KeyNotFound,
                "node software key store lock failed",
            )
        })?
        .get(key_id)
        .cloned()
        .ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::KeyNotFound,
                format!("node software key not found: {key_id}"),
            )
        })?;
    SecretKey::from_slice(signing_key.to_bytes().as_slice()).map_err(|_| {
        CoreError::new(
            CoreErrorCode::InvalidKey,
            "node software key is not a valid P-256 ECDH key",
        )
    })
}

fn jwe_public_jwk_for_key_id(key_id: &str) -> CoreResult<JwePublicJwk> {
    let secret = secret_key_for_key_id(key_id)?;
    Ok(JwePublicJwk::from_public_key(
        secret.public_key(),
        Some(key_id.to_owned()),
        Some("ECDH-ES".to_owned()),
    ))
}

fn public_jwk_from_signing_key(signing_key: &SigningKey, kid: Option<String>) -> PublicJwk {
    let point = signing_key.verifying_key().to_sec1_point(false);
    let x = point.x().expect("uncompressed P-256 point has x");
    let y = point.y().expect("uncompressed P-256 point has y");
    PublicJwk::p256(b64_encode(x), b64_encode(y), kid)
}

fn fixed_salt_source_from_json(salts_json: &str) -> NapiResult<FixedSaltSource> {
    let salts: Vec<String> = parse(salts_json)?;
    Ok(FixedSaltSource::new(
        salts
            .into_iter()
            .map(|salt| b64_decode(&salt))
            .collect::<CoreResult<Vec<_>>>()
            .map_err(to_napi_error)?,
    ))
}

fn resolver_from_json(resolver_responses_json: &str) -> NapiResult<JsonMapResolver> {
    let responses: HashMap<String, String> = parse(resolver_responses_json)?;
    Ok(JsonMapResolver {
        responses: responses
            .into_iter()
            .map(|(url, body)| (url, body.into_bytes()))
            .collect(),
    })
}

fn parse<T: serde::de::DeserializeOwned>(json: &str) -> NapiResult<T> {
    serde_json::from_str(json).map_err(|error| {
        NapiError::new(
            Status::InvalidArg,
            format!("invalid JSON passed to native binding: {error}"),
        )
    })
}

fn serialize<T: serde::Serialize>(value: &T) -> NapiResult<String> {
    serde_json::to_string(value).map_err(|error| {
        NapiError::new(
            Status::GenericFailure,
            format!("native binding JSON serialization failed: {error}"),
        )
    })
}

fn to_napi_error(error: CoreError) -> NapiError {
    NapiError::new(
        Status::GenericFailure,
        format!("{}: {}", error_code_label(error.code()), error.message()),
    )
}

fn error_code_label(code: CoreErrorCode) -> String {
    serde_json::to_string(&code)
        .map(|value| value.trim_matches('"').to_owned())
        .unwrap_or_else(|_| format!("{code:?}"))
}

#[cfg(test)]
mod tests {
    use super::crate_name_raw;

    #[test]
    fn links_identity_core() {
        assert_eq!(crate_name_raw(), "identity-core");
    }
}
