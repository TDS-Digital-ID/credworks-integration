//! JSON/opaque-handle adapters only; the registry is the Node signing consumer.
use identity_core::{
    IssuerAuthorizationRequest, IssuerAuthorizations, JwsHeader, KeyId, PublicJwk,
    ScalarCredentialDefinition, SubjectValidationMode,
};
use napi::Result;
use napi_derive::napi;
fn parse<T: serde::de::DeserializeOwned>(json: &str) -> Result<T> {
    serde_json::from_str(json).map_err(|_| {
        super::to_napi_error(identity_core::CoreError::new(
            identity_core::CoreErrorCode::JsonSerialization,
            "invalid scalar definition/authority JSON",
        ))
    })
}
#[napi(js_name = "validateScalarDefinitionRaw")]
pub fn validate_scalar_definition_raw(definition_json: String) -> Result<()> {
    identity_core::validate_scalar_definition(&parse::<ScalarCredentialDefinition>(
        &definition_json,
    )?)
    .map_err(super::to_napi_error)
}
#[napi(js_name = "validateScalarSubjectRaw")]
pub fn validate_scalar_subject_raw(
    definition_json: String,
    subject_json: String,
    mode_json: String,
) -> Result<()> {
    identity_core::validate_scalar_subject(
        &parse::<ScalarCredentialDefinition>(&definition_json)?,
        &parse::<serde_json::Value>(&subject_json)?,
        parse::<SubjectValidationMode>(&mode_json)?,
    )
    .map_err(super::to_napi_error)
}
#[napi(js_name = "signIssuerAuthorizationsRaw")]
pub fn sign_issuer_authorizations_raw(
    payload_json: String,
    header_json: String,
    key_id: String,
) -> Result<String> {
    identity_core::sign_issuer_authorizations(
        &parse::<IssuerAuthorizations>(&payload_json)?,
        &parse::<JwsHeader>(&header_json)?,
        &super::NodeSoftwareSigner,
        &KeyId::new(key_id),
    )
    .map_err(super::to_napi_error)
}
#[napi(js_name = "verifyIssuerAuthorizationRaw")]
pub fn verify_issuer_authorization_raw(
    compact: String,
    anchor_json: String,
    request_json: String,
    now: i64,
) -> Result<String> {
    super::serialize(
        &identity_core::verify_issuer_authorization(
            &compact,
            &parse::<PublicJwk>(&anchor_json)?,
            &parse::<IssuerAuthorizationRequest>(&request_json)?,
            now,
        )
        .map_err(super::to_napi_error)?,
    )
}
#[napi(js_name = "verifyScalarCredentialAuthorizationRaw")]
pub fn verify_scalar_credential_authorization_raw(
    credential: String,
    issuer_key_json: String,
    authorization: String,
    anchor_json: String,
    registry_did: String,
    now: i64,
    mode_json: String,
) -> Result<String> {
    super::serialize(
        &identity_core::verify_scalar_credential_authorization(
            &credential,
            &parse::<PublicJwk>(&issuer_key_json)?,
            &authorization,
            &parse::<PublicJwk>(&anchor_json)?,
            &registry_did,
            now,
            parse::<SubjectValidationMode>(&mode_json)?,
        )
        .map_err(super::to_napi_error)?,
    )
}
