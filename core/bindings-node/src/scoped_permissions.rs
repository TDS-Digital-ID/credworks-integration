//! Thin adapter for the core's distinctly typed verifier permission document.
use identity_core::{
    JwsHeader, KeyId, PublicJwk, ScopedVerifierPermissionRequest, ScopedVerifierPermissions,
    sign_scoped_verifier_permissions, verify_scoped_verifier_permission,
};
use napi::Result;
use napi_derive::napi;

#[napi(js_name = "signScopedVerifierPermissionsRaw")]
pub fn sign_scoped_verifier_permissions_raw(
    payload_json: String,
    header_json: String,
    key_id: String,
) -> Result<String> {
    let payload: ScopedVerifierPermissions = parse(&payload_json)?;
    let header: JwsHeader = parse(&header_json)?;
    sign_scoped_verifier_permissions(
        &payload,
        &header,
        &super::NodeSoftwareSigner,
        &KeyId::new(key_id),
    )
    .map_err(super::to_napi_error)
}

#[napi(js_name = "verifyScopedVerifierPermissionRaw")]
pub fn verify_scoped_verifier_permission_raw(
    compact_jws: String,
    trust_anchor_jwk_json: String,
    request_json: String,
    now_unix_seconds: i64,
) -> Result<String> {
    let anchor: PublicJwk = parse(&trust_anchor_jwk_json)?;
    let request: ScopedVerifierPermissionRequest = parse(&request_json)?;
    super::serialize(
        &verify_scoped_verifier_permission(&compact_jws, &anchor, &request, now_unix_seconds)
            .map_err(super::to_napi_error)?,
    )
}

fn parse<T: serde::de::DeserializeOwned>(json: &str) -> Result<T> {
    serde_json::from_str(json).map_err(|_| {
        super::to_napi_error(identity_core::CoreError::new(
            identity_core::CoreErrorCode::JsonSerialization,
            "invalid scoped permission JSON",
        ))
    })
}

#[napi(js_name = "verifyPartnerIdentityProofRaw")]
pub fn verify_partner_identity_proof_raw(
    jwt: String,
    public_jwk_json: String,
    options_json: String,
) -> Result<()> {
    let key: PublicJwk = parse(&public_jwk_json)?;
    let options: identity_core::PartnerIdentityProofOptions = parse(&options_json)?;
    identity_core::verify_partner_identity_proof(&jwt, &key, &options).map_err(super::to_napi_error)
}
