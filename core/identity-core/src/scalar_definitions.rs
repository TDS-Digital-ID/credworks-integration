//! Bounded scalar vocabulary; namespace ownership is established by the registry, not validation.
use crate::{CoreError, CoreErrorCode, CoreResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use url::Url;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScalarCredentialDefinition {
    pub id: String,
    pub version: String,
    pub credential_type: String,
    pub label: String,
    pub max_validity_seconds: i64,
    pub claims: Vec<ScalarClaim>,
    pub profiles: Vec<ScalarDisclosureProfile>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScalarClaim {
    pub name: String,
    pub label: String,
    pub value_type: ScalarValueType,
    pub required: bool,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScalarDisclosureProfile {
    pub name: String,
    pub claim_paths: Vec<Vec<String>>,
}
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScalarValueType {
    String,
    Boolean,
    Integer,
    Number,
}
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubjectValidationMode {
    Complete,
    Disclosed,
}
fn invalid(message: &str) -> CoreError {
    CoreError::new(CoreErrorCode::InvalidInput, message)
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
const RESERVED: &[&str] = &[
    "vc",
    "vp",
    "alg",
    "typ",
    "jwk",
    "credential_definition",
    "credential_status",
    "credential_subject",
    "valid_from",
    "valid_until",
    "id",
    "type",
    "issuer",
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "nbf",
    "jti",
    "cnf",
    "kid",
    "holder",
    "proof",
    "credentialdefinition",
    "credentialsubject",
    "credentialstatus",
    "credentialschema",
    "validfrom",
    "validuntil",
    "issuancedate",
    "expirationdate",
    "status",
    "vct",
    "_sd",
    "_sd_alg",
    "sd_hash",
];
pub fn validate_scalar_definition(definition: &ScalarCredentialDefinition) -> CoreResult<()> {
    let url = Url::parse(&definition.id)
        .map_err(|_| invalid("definition ID must be namespaced HTTPS or URN"))?;
    if definition.id.is_empty()
        || definition.id.len() > 256
        || definition.id.chars().any(char::is_whitespace)
        || !matches!(url.scheme(), "https" | "urn")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || definition
            .id
            .to_ascii_lowercase()
            .starts_with("urn:credworks:")
        || (url.scheme() == "urn"
            && url.path().split_once(':').is_none_or(|(ns, name)| {
                ns.is_empty()
                    || name.is_empty()
                    || !ns.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            }))
    {
        return Err(invalid("invalid or reserved definition namespace"));
    }
    let typ = &definition.credential_type;
    if !identifier(&definition.version)
        || typ.is_empty()
        || typ.len() > 128
        || !typ.as_bytes()[0].is_ascii_alphabetic()
        || !typ.bytes().all(|b| b.is_ascii_alphanumeric())
        || [
            "VerifiableCredential",
            "UniversityEducationCredential",
            "UniversityStaffCredential",
            "StaffAffiliationCredential",
            "RoleAuthorityCredential",
            "VisaWorkRightsCredential",
            "GovernmentIdentityCredential",
            "WalletInstanceAttestation",
            "BitstringStatusListCredential",
        ]
        .contains(&typ.as_str())
        || !label(&definition.label)
        || !(1..=31_536_000).contains(&definition.max_validity_seconds)
    {
        return Err(invalid(
            "invalid definition type, version, label or lifetime",
        ));
    }
    if definition.claims.is_empty()
        || definition.claims.len() > 64
        || definition.profiles.is_empty()
        || definition.profiles.len() > 16
    {
        return Err(invalid("definition requires bounded claims and profiles"));
    }
    let mut claims = HashSet::new();
    for claim in &definition.claims {
        if claim.name.is_empty()
            || claim.name.len() > 64
            || !claim.name.as_bytes()[0].is_ascii_lowercase()
            || !claim
                .name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            || RESERVED.contains(&claim.name.to_ascii_lowercase().as_str())
            || !label(&claim.label)
            || !claims.insert(&claim.name)
        {
            return Err(invalid("invalid, reserved or duplicate scalar claim"));
        }
    }
    let mut profiles = HashSet::new();
    for profile in &definition.profiles {
        if !identifier(&profile.name)
            || !profiles.insert(&profile.name)
            || profile.claim_paths.is_empty()
            || profile.claim_paths.len() > 64
        {
            return Err(invalid("invalid or duplicate disclosure profile"));
        }
        let mut paths = HashSet::new();
        for path in &profile.claim_paths {
            if path.len() != 2
                || path[0] != "credentialSubject"
                || !claims.contains(&path[1])
                || !paths.insert(path)
            {
                return Err(invalid(
                    "disclosure path must name one unique declared scalar claim",
                ));
            }
        }
    }
    Ok(())
}
pub fn validate_scalar_subject(
    definition: &ScalarCredentialDefinition,
    subject: &Value,
    mode: SubjectValidationMode,
) -> CoreResult<()> {
    validate_scalar_definition(definition)?;
    let object = subject
        .as_object()
        .ok_or_else(|| invalid("scalar subject must be an object"))?;
    if object
        .keys()
        .any(|name| !definition.claims.iter().any(|claim| &claim.name == name))
    {
        return Err(invalid("undeclared scalar subject claim"));
    }
    for claim in &definition.claims {
        let Some(value) = object.get(&claim.name) else {
            if claim.required && mode == SubjectValidationMode::Complete {
                return Err(invalid("required scalar claim is missing"));
            }
            continue;
        };
        let valid = match claim.value_type {
            ScalarValueType::String => value.as_str().is_some_and(|value| value.len() <= 1024),
            ScalarValueType::Boolean => value.is_boolean(),
            ScalarValueType::Integer | ScalarValueType::Number => {
                value.as_f64().is_some_and(|number| {
                    number.is_finite()
                        && number.abs() <= 9_007_199_254_740_991.0
                        && (claim.value_type == ScalarValueType::Number || number.fract() == 0.0)
                })
            }
        };
        if !valid {
            return Err(invalid(
                "scalar claim value does not match its declared type or bounds",
            ));
        }
    }
    Ok(())
}
