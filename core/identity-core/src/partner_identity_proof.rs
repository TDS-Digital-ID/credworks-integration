//! Application ownership proof; replay consumption belongs to the registry store.
use crate::{CoreError, CoreErrorCode, CoreResult, JwsHeader, PublicJwk, verify_compact_jws_json};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartnerIdentityProofOptions {
    pub issuer: String,
    pub key_id: String,
    pub audience: String,
    pub nonce: String,
    pub now_unix_seconds: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    iss: String,
    aud: String,
    nonce: String,
    iat: i64,
    exp: i64,
}

pub fn verify_partner_identity_proof(
    jwt: &str,
    key: &PublicJwk,
    expected: &PartnerIdentityProofOptions,
) -> CoreResult<()> {
    let (header, claims): (JwsHeader, Claims) = verify_compact_jws_json(jwt, key)?;
    let ttl = claims.exp.checked_sub(claims.iat);
    let audience = url::Url::parse(&expected.audience).ok();
    let issuer = crate::did_web_to_https_url(&expected.issuer)
        .ok()
        .and_then(|url| url::Url::parse(&url).ok());
    if !audience.is_some_and(|url| {
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
    }) || !issuer.is_some_and(|url| {
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
    }) || expected.issuer.contains('/')
        || expected.issuer.chars().any(char::is_whitespace)
        || expected.key_id == format!("{}#", expected.issuer)
        || header.typ.as_deref() != Some("partner-identity-proof+jwt")
        || header.kid.as_deref() != Some(expected.key_id.as_str())
        || claims.iss != expected.issuer
        || claims.aud != expected.audience
        || claims.nonce != expected.nonce
        || expected.nonce.len() < 8
        || expected.nonce.len() > 256
        || !expected
            .key_id
            .starts_with(&format!("{}#", expected.issuer))
        || claims.iat > expected.now_unix_seconds
        || claims.exp <= expected.now_unix_seconds
        || !matches!(ttl, Some(1..=60))
    {
        return Err(CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "ownership proof does not match fresh challenge",
        ));
    }
    Ok(())
}
