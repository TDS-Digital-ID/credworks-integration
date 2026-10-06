//! Exact issuer/key/definition authority, separate from legacy type-only trust.
use crate::{
    CoreError, CoreErrorCode, CoreResult, JwsHeader, KeyId, PublicJwk, ScalarCredentialDefinition,
    Signer, TrustListStatus, b64_decode, did_web_to_https_url, public_jwk_sha256_thumbprint,
    sign_compact_jws_json, validate_scalar_definition, verify_compact_jws_json,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use url::Url;
pub const ISSUER_AUTHORIZATIONS_TYP: &str = "issuer-authorizations+jwt";
pub const ISSUER_AUTHORIZATIONS_MAX_TTL_SECONDS: i64 = 86_400;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKeyState {
    Current,
    Retained,
    Withdrawn,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuerAuthorityPurpose {
    Issuance,
    Verification,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerStatusAuthority {
    pub key_id: String,
    pub public_jwk_sha256_thumbprint: String,
}
// Missing optional fields preserve legacy bytes; explicit null is unsupported vocabulary.
fn present<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerAuthorizations {
    pub version: u32,
    pub id: String,
    pub issuer: String,
    pub iat: i64,
    pub exp: i64,
    pub authorizations: Vec<IssuerAuthorization>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerAuthorization {
    pub credential_issuer_did: String,
    pub credential_issuer_key_id: String,
    pub credential_issuer_public_jwk_sha256_thumbprint: String,
    pub definition: ScalarCredentialDefinition,
    pub status: TrustListStatus,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub key_state: Option<CredentialKeyState>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub status_authority: Option<IssuerStatusAuthority>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerAuthorizationRequest {
    pub registry_did: String,
    pub credential_issuer_did: String,
    pub credential_issuer_key_id: String,
    pub credential_issuer_public_jwk: PublicJwk,
    pub definition_id: String,
    pub definition_version: String,
    pub credential_type: String,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub purpose: Option<IssuerAuthorityPurpose>,
}
fn denied(message: &str) -> CoreError {
    CoreError::new(CoreErrorCode::TrustCheckFailed, message)
}
fn valid_did(did: &str) -> CoreResult<()> {
    let url =
        Url::parse(&did_web_to_https_url(did).map_err(|_| denied("invalid authorization DID"))?)
            .map_err(|_| denied("invalid authorization DID"))?;
    if did.len() > 512
        || did.contains('/')
        || did.chars().any(char::is_whitespace)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(denied("ambiguous authorization DID"));
    }
    Ok(())
}
fn valid_key_id(did: &str, key_id: &str) -> CoreResult<()> {
    let Some(fragment) = key_id.strip_prefix(&format!("{did}#")) else {
        return Err(denied("issuer key ID must belong to exact issuer"));
    };
    if fragment.is_empty()
        || fragment.len() > 128
        || !fragment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(denied("invalid issuer key fragment"));
    }
    Ok(())
}
fn validate_document(document: &IssuerAuthorizations) -> CoreResult<()> {
    valid_did(&document.issuer)?;
    let id = Url::parse(&document.id).map_err(|_| denied("invalid authorization document ID"))?;
    if document.version != 1
        || document.id.len() > 1024
        || id.scheme() != "https"
        || !id.username().is_empty()
        || id.password().is_some()
        || id.fragment().is_some()
        || id.query().is_some()
        || document.iat >= document.exp
        || document
            .exp
            .checked_sub(document.iat)
            .is_none_or(|ttl| ttl > ISSUER_AUTHORIZATIONS_MAX_TTL_SECONDS)
        || document.authorizations.len() > 64
    {
        return Err(denied(
            "unsupported authorization version, identity or lifetime",
        ));
    }
    let mut scopes = HashSet::new();
    let mut definitions = HashMap::new();
    let mut keys = HashMap::new();
    let mut status_authorities = HashMap::new();
    let mut current_keys = HashMap::new();
    let mut issuer_keys: HashMap<&str, HashSet<&str>> = HashMap::new();
    let mut legacy_issuers = HashSet::new();
    for grant in &document.authorizations {
        valid_did(&grant.credential_issuer_did)?;
        valid_key_id(
            &grant.credential_issuer_did,
            &grant.credential_issuer_key_id,
        )?;
        if grant.key_state.is_some() != grant.status_authority.is_some() {
            return Err(denied(
                "key state and status authority must be declared together",
            ));
        }
        if let Some(status) = &grant.status_authority {
            valid_key_id(&grant.credential_issuer_did, &status.key_id)?;
            if b64_decode(&status.public_jwk_sha256_thumbprint).map_or(true, |pin| pin.len() != 32)
            {
                return Err(denied("invalid status key pin"));
            }
        }
        let did = grant.credential_issuer_did.as_str();
        let key_id = grant.credential_issuer_key_id.as_str();
        let pin = grant
            .credential_issuer_public_jwk_sha256_thumbprint
            .as_str();
        let state = grant.key_state.unwrap_or(CredentialKeyState::Current);
        if keys
            .insert((did, key_id), (pin, state))
            .is_some_and(|previous| previous != (pin, state))
        {
            return Err(denied(
                "conflicting credential key pin or state across definitions",
            ));
        }
        if state == CredentialKeyState::Current
            && current_keys
                .insert(did, key_id)
                .is_some_and(|previous| previous != key_id)
        {
            return Err(denied("multiple current credential keys for issuer"));
        }
        issuer_keys.entry(did).or_default().insert(key_id);
        if grant.key_state.is_none() {
            legacy_issuers.insert(did);
        }
        let status = grant
            .status_authority
            .as_ref()
            .map_or((key_id, pin), |status| {
                (
                    status.key_id.as_str(),
                    status.public_jwk_sha256_thumbprint.as_str(),
                )
            });
        if status_authorities
            .insert(did, status)
            .is_some_and(|previous| previous != status)
        {
            return Err(denied("conflicting status authority for issuer"));
        }
        validate_scalar_definition(&grant.definition)?;
        if definitions
            .insert(
                (&grant.definition.id, &grant.definition.version),
                &grant.definition,
            )
            .is_some_and(|previous| previous != &grant.definition)
        {
            return Err(denied("conflicting shared definition version"));
        }
        if b64_decode(&grant.credential_issuer_public_jwk_sha256_thumbprint)
            .map_or(true, |pin| pin.len() != 32)
            || !scopes.insert((
                &grant.credential_issuer_did,
                &grant.credential_issuer_key_id,
                &grant.definition.id,
                &grant.definition.version,
            ))
        {
            return Err(denied(
                "invalid key pin or duplicate issuer definition scope",
            ));
        }
    }
    if legacy_issuers.iter().any(|did| issuer_keys[did].len() > 1) {
        return Err(denied(
            "multi-key issuer history requires explicit key state",
        ));
    }
    for (did, (key_id, pin)) in status_authorities {
        if keys
            .get(&(did, key_id))
            .is_some_and(|(credential_pin, _)| *credential_pin != pin)
        {
            return Err(denied("status authority reassigns an existing key ID"));
        }
    }
    Ok(())
}
fn validate_header(header: &JwsHeader, registry: &str) -> CoreResult<()> {
    if header.typ.as_deref() != Some(ISSUER_AUTHORIZATIONS_TYP) {
        return Err(denied("expected issuer-authorizations+jwt"));
    }
    valid_key_id(
        registry,
        header
            .kid
            .as_deref()
            .ok_or_else(|| denied("authorization signing key ID required"))?,
    )
}
pub fn sign_issuer_authorizations(
    document: &IssuerAuthorizations,
    header: &JwsHeader,
    signer: &impl Signer,
    key_id: &KeyId,
) -> CoreResult<String> {
    validate_document(document)?;
    validate_header(header, &document.issuer)?;
    sign_compact_jws_json(header, document, signer, key_id)
}
pub fn verify_issuer_authorization(
    compact: &str,
    anchor: &PublicJwk,
    request: &IssuerAuthorizationRequest,
    now: i64,
) -> CoreResult<IssuerAuthorization> {
    let (header, payload): (JwsHeader, serde_json::Value) =
        verify_compact_jws_json(compact, anchor)?;
    let document: IssuerAuthorizations = serde_json::from_value(payload).map_err(|_| {
        CoreError::new(
            CoreErrorCode::JsonSerialization,
            "invalid issuer authorization document",
        )
    })?;
    validate_document(&document)?;
    validate_header(&header, &document.issuer)?;
    if document.issuer != request.registry_did {
        return Err(denied("authorization registry identity mismatch"));
    }
    if now < document.iat || now >= document.exp {
        return Err(CoreError::new(
            CoreErrorCode::FreshnessCheckFailed,
            "issuer authorization outside validity window",
        ));
    }
    let pin = public_jwk_sha256_thumbprint(&request.credential_issuer_public_jwk)?;
    document
        .authorizations
        .into_iter()
        .find(|grant| {
            grant.status == TrustListStatus::Active
                && match grant.key_state.unwrap_or(CredentialKeyState::Current) {
                    CredentialKeyState::Current => true,
                    CredentialKeyState::Retained => {
                        request.purpose == Some(IssuerAuthorityPurpose::Verification)
                    }
                    CredentialKeyState::Withdrawn => false,
                }
                && grant.credential_issuer_did == request.credential_issuer_did
                && grant.credential_issuer_key_id == request.credential_issuer_key_id
                && grant.credential_issuer_public_jwk_sha256_thumbprint == pin
                && grant.definition.id == request.definition_id
                && grant.definition.version == request.definition_version
                && grant.definition.credential_type == request.credential_type
        })
        .ok_or_else(|| {
            denied("no active authorization for exact issuer/key/definition/version/type")
        })
}

/// Authenticate the actual W3C issuer token before selecting authority. Does not verify KB-JWT/status.
pub fn verify_scalar_credential_authorization(
    compact_credential: &str,
    issuer_key: &PublicJwk,
    compact_authorization: &str,
    anchor: &PublicJwk,
    registry_did: &str,
    now: i64,
    mode: crate::SubjectValidationMode,
) -> CoreResult<crate::VerifiedSdJwtCredential> {
    verify_scalar_credential_at_times(
        compact_credential,
        issuer_key,
        compact_authorization,
        anchor,
        registry_did,
        (now, now),
        mode,
    )
}

/// Authenticate an exact renewal predecessor at its signed issuance time, with current authority.
/// Does not verify current status or confer presentation validity. No caller-selected backdating.
pub fn verify_scalar_renewal_predecessor(
    compact_credential: &str,
    issuer_key: &PublicJwk,
    compact_authorization: &str,
    anchor: &PublicJwk,
    registry_did: &str,
    authority_now: i64,
) -> CoreResult<crate::VerifiedSdJwtCredential> {
    let (issuer_jwt, _, _) = crate::split_sd_jwt(compact_credential)?;
    let (_, authenticated_payload): (JwsHeader, serde_json::Value) =
        verify_compact_jws_json(issuer_jwt, issuer_key)?;
    let credential_time = authenticated_payload
        .get("iat")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| denied("credential iat required"))?;
    if credential_time > authority_now {
        return Err(CoreError::new(
            CoreErrorCode::FreshnessCheckFailed,
            "renewal predecessor issued after authority observation",
        ));
    }
    verify_scalar_credential_at_times(
        compact_credential,
        issuer_key,
        compact_authorization,
        anchor,
        registry_did,
        (credential_time, authority_now),
        crate::SubjectValidationMode::Complete,
    )
}

fn verify_scalar_credential_at_times(
    compact_credential: &str,
    issuer_key: &PublicJwk,
    compact_authorization: &str,
    anchor: &PublicJwk,
    registry_did: &str,
    times: (i64, i64),
    mode: crate::SubjectValidationMode,
) -> CoreResult<crate::VerifiedSdJwtCredential> {
    let verified = crate::verify_sd_jwt_credential(
        compact_credential,
        issuer_key,
        &crate::SdJwtCredentialVerificationOptions {
            now_unix_seconds: times.0,
            required_claims: vec![],
            format: crate::CredentialFormat::W3cVcDataModel,
        },
    )?;
    let payload = &verified.processed_payload;
    let reference = payload
        .get("credentialDefinition")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| denied("signed credential definition reference required"))?;
    if reference.len() != 2
        || verified
            .disclosed_claim_paths
            .iter()
            .any(|path| path.first().is_none_or(|root| root != "credentialSubject"))
    {
        return Err(denied(
            "protocol fields and definition reference must remain always visible",
        ));
    }
    let text = |value: Option<&serde_json::Value>| -> CoreResult<String> {
        value
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| denied("signed credential scope must be explicit strings"))
    };
    let types = payload
        .get("type")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| denied("credential type array required"))?;
    if types.len() != 2 || types[0].as_str() != Some("VerifiableCredential") {
        return Err(denied("exact generic credential type required"));
    }
    let request = IssuerAuthorizationRequest {
        registry_did: registry_did.into(),
        credential_issuer_did: text(payload.get("iss"))?,
        credential_issuer_key_id: verified
            .issuer_header
            .kid
            .clone()
            .ok_or_else(|| denied("signed issuer key ID required"))?,
        credential_issuer_public_jwk: issuer_key.clone(),
        definition_id: text(reference.get("id"))?,
        definition_version: text(reference.get("version"))?,
        credential_type: text(types.get(1))?,
        purpose: Some(IssuerAuthorityPurpose::Verification),
    };
    let grant = verify_issuer_authorization(compact_authorization, anchor, &request, times.1)?;
    if verified.disclosed_claim_paths.iter().any(|path| {
        !grant
            .definition
            .claims
            .iter()
            .any(|claim| claim.full_path() == *path)
    }) {
        return Err(denied(
            "disclosure must name an exact authorized claim path",
        ));
    }
    let iat = payload
        .get("iat")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| denied("credential iat required"))?;
    let exp = payload
        .get("exp")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| denied("credential exp required"))?;
    if exp
        .checked_sub(iat)
        .is_none_or(|ttl| ttl <= 0 || ttl > grant.definition.max_validity_seconds)
        || payload.get("credentialStatus").is_none()
    {
        return Err(denied(
            "credential lifetime/status violates definition protocol",
        ));
    }
    for (name, expected) in [("validFrom", iat), ("validUntil", exp)] {
        let instant = payload
            .get(name)
            .and_then(serde_json::Value::as_str)
            .and_then(|text| {
                time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339)
                    .ok()
            })
            .ok_or_else(|| denied("generic credential validity instants required"))?;
        if instant.unix_timestamp() != expected || instant.nanosecond() != 0 {
            return Err(denied(
                "credential date validity must match signed integer JWT validity",
            ));
        }
    }
    let holder: PublicJwk = serde_json::from_value(
        payload
            .get("cnf")
            .and_then(|cnf| cnf.get("jwk"))
            .cloned()
            .ok_or_else(|| denied("credential holder key required"))?,
    )
    .map_err(|_| denied("invalid credential holder key"))?;
    public_jwk_sha256_thumbprint(&holder)?;
    let mut subject = payload
        .get("credentialSubject")
        .cloned()
        .ok_or_else(|| denied("credential subject required"))?;
    crate::scalar_definitions::remove_structural_sd_metadata(
        &grant.definition,
        &mut subject,
        &mut vec!["credentialSubject".into()],
    );
    crate::validate_scalar_subject(&grant.definition, &subject, mode)?;
    Ok(verified)
}
