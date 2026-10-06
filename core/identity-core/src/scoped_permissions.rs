//! Application-level verifier permissions. Kept separate from legacy trust lists.
use crate::{
    CoreError, CoreErrorCode, CoreResult, JwsHeader, KeyId, PublicJwk, Signer, TrustListStatus,
    did_web_to_https_url, public_jwk_sha256_thumbprint, sign_compact_jws_json,
    verify_compact_jws_json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use url::Url;

pub const SCOPED_VERIFIER_PERMISSIONS_TYP: &str = "scoped-verifier-permissions+jwt";
pub const SCOPED_VERIFIER_PERMISSIONS_VERSION: u32 = 1;
pub const SCOPED_VERIFIER_PERMISSIONS_MAX_TTL_SECONDS: i64 = 86_400;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedVerifierPermissions {
    pub version: u32,
    pub id: String,
    pub issuer: String,
    pub iat: i64,
    pub exp: i64,
    pub permissions: Vec<ScopedVerifierPermission>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedVerifierPermission {
    pub credential_issuer_did: String,
    pub definition_id: String,
    pub definition_version: String,
    pub credential_type: String,
    pub verifier_did: String,
    pub verifier_origin: String,
    pub verifier_public_jwk_sha256_thumbprint: String,
    pub profile_name: String,
    pub claim_paths: Vec<Vec<String>>,
    pub status: TrustListStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedVerifierPermissionRequest {
    pub credential_issuer_did: String,
    pub definition_id: String,
    pub definition_version: String,
    pub credential_type: String,
    pub verifier_did: String,
    pub verifier_origin: String,
    pub verifier_public_jwk: PublicJwk,
    pub profile_name: String,
    pub claim_paths: Vec<Vec<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScopedVerifierPermissionResult {
    pub permission: ScopedVerifierPermission,
    pub claim_paths: Vec<Vec<String>>,
    pub active: bool,
}

pub fn sign_scoped_verifier_permissions(
    payload: &ScopedVerifierPermissions,
    header: &JwsHeader,
    signer: &impl Signer,
    key_id: &KeyId,
) -> CoreResult<String> {
    validate_document(payload)?;
    validate_header(header)?;
    sign_compact_jws_json(header, payload, signer, key_id)
}

pub fn verify_scoped_verifier_permission(
    compact_jws: &str,
    trust_anchor_jwk: &PublicJwk,
    request: &ScopedVerifierPermissionRequest,
    now_unix_seconds: i64,
) -> CoreResult<ScopedVerifierPermissionResult> {
    let (header, payload): (JwsHeader, serde_json::Value) =
        verify_compact_jws_json(compact_jws, trust_anchor_jwk)?;
    validate_header(&header)?;
    let payload: ScopedVerifierPermissions = serde_json::from_value(payload).map_err(|_| {
        CoreError::new(
            CoreErrorCode::JsonSerialization,
            "invalid scoped permission document",
        )
    })?;
    validate_document(&payload)?;
    if now_unix_seconds < payload.iat || now_unix_seconds >= payload.exp {
        return Err(denied(
            "scoped permission document is outside its validity window",
        ));
    }
    validate_paths(&request.claim_paths)?;
    let pin = public_jwk_sha256_thumbprint(&request.verifier_public_jwk)?;
    let grant = payload
        .permissions
        .iter()
        .find(|grant| {
            grant.credential_issuer_did == request.credential_issuer_did
                && grant.definition_id == request.definition_id
                && grant.definition_version == request.definition_version
                && grant.credential_type == request.credential_type
                && grant.verifier_did == request.verifier_did
                && grant.verifier_origin == request.verifier_origin
                && grant.profile_name == request.profile_name
                && grant.verifier_public_jwk_sha256_thumbprint == pin
                && grant.status == TrustListStatus::Active
        })
        .ok_or_else(|| denied("no active permission matches the exact requested scope and key"))?;
    if request
        .claim_paths
        .iter()
        .any(|path| !grant.claim_paths.contains(path))
    {
        return Err(denied("requested paths exceed scoped verifier permission"));
    }
    Ok(ScopedVerifierPermissionResult {
        permission: grant.clone(),
        claim_paths: request.claim_paths.clone(),
        active: true,
    })
}

fn validate_header(header: &JwsHeader) -> CoreResult<()> {
    if header.typ.as_deref() != Some(SCOPED_VERIFIER_PERMISSIONS_TYP) {
        return Err(denied("expected scoped-verifier-permissions+jwt document"));
    }
    Ok(())
}
fn validate_document(document: &ScopedVerifierPermissions) -> CoreResult<()> {
    if document.version != SCOPED_VERIFIER_PERMISSIONS_VERSION {
        return Err(denied("unsupported scoped permission document version"));
    }
    validate_did(&document.issuer)?;
    if document.id.is_empty()
        || document.iat >= document.exp
        || document
            .exp
            .checked_sub(document.iat)
            .is_none_or(|ttl| ttl > SCOPED_VERIFIER_PERMISSIONS_MAX_TTL_SECONDS)
    {
        return Err(denied(
            "invalid scoped permission document identity or lifetime",
        ));
    }
    let mut scopes = HashSet::new();
    for grant in &document.permissions {
        validate_did(&grant.credential_issuer_did)?;
        let did_url = validate_did(&grant.verifier_did)?;
        let origin = Url::parse(&grant.verifier_origin)
            .map_err(|_| denied("invalid verifier HTTPS origin"))?;
        if origin.scheme() != "https"
            || origin.origin().ascii_serialization() != grant.verifier_origin
            || origin.origin() != did_url.origin()
        {
            return Err(denied("verifier DID and canonical HTTPS origin must match"));
        }
        let definition =
            Url::parse(&grant.definition_id).map_err(|_| denied("invalid definition namespace"))?;
        if !matches!(definition.scheme(), "https" | "urn")
            || definition.username() != ""
            || definition.password().is_some()
            || definition.fragment().is_some()
            || grant.definition_id.chars().any(char::is_whitespace)
            || (definition.scheme() == "urn"
                && definition
                    .path()
                    .split_once(':')
                    .is_none_or(|(namespace, name)| {
                        namespace.is_empty()
                            || name.is_empty()
                            || !namespace
                                .chars()
                                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
                    }))
        {
            return Err(denied(
                "definition identifier must be namespaced HTTPS or URN",
            ));
        }
        for value in [
            &grant.definition_version,
            &grant.credential_type,
            &grant.profile_name,
        ] {
            if value.is_empty() || value.len() > 256 || value.chars().any(char::is_whitespace) {
                return Err(denied("scope fields must be nonempty exact identifiers"));
            }
        }
        if crate::b64_decode(&grant.verifier_public_jwk_sha256_thumbprint)
            .map_or(true, |pin| pin.len() != 32)
        {
            return Err(denied("invalid verifier public key thumbprint"));
        }
        validate_paths(&grant.claim_paths)?;
        if !scopes.insert((
            &grant.credential_issuer_did,
            &grant.definition_id,
            &grant.definition_version,
            &grant.credential_type,
            &grant.verifier_did,
            &grant.verifier_origin,
            &grant.profile_name,
        )) {
            return Err(denied("duplicate scoped verifier permission"));
        }
    }
    Ok(())
}
fn validate_did(did: &str) -> CoreResult<Url> {
    let url = Url::parse(
        &did_web_to_https_url(did).map_err(|_| denied("invalid scoped permission DID"))?,
    )
    .map_err(|_| denied("invalid scoped permission DID URL"))?;
    if did.contains('/')
        || did.chars().any(char::is_whitespace)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(denied(
            "scoped permission DID must have an unambiguous HTTPS identity",
        ));
    }
    Ok(url)
}
fn validate_paths(paths: &[Vec<String>]) -> CoreResult<()> {
    if paths.is_empty() || paths.len() > 64 {
        return Err(denied("claim path set must contain 1 to 64 exact paths"));
    }
    for (index, path) in paths.iter().enumerate() {
        if path.len() < 2
            || path.len() > 16
            || path[0] != "credentialSubject"
            || path.iter().any(|component| {
                component.is_empty()
                    || component.len() > 256
                    || component == "*"
                    || component.chars().any(char::is_control)
                    || component.chars().all(|ch| ch.is_ascii_digit())
            })
        {
            return Err(denied("unsupported claim path shape"));
        }
        if paths[..index]
            .iter()
            .any(|other| path.starts_with(other) || other.starts_with(path))
        {
            return Err(denied(
                "duplicate or overlapping claim paths are unsupported",
            ));
        }
    }
    Ok(())
}
fn denied(message: &str) -> CoreError {
    CoreError::new(CoreErrorCode::TrustCheckFailed, message)
}
