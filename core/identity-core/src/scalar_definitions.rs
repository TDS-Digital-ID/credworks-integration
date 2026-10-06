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
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_claim_path"
    )]
    pub path: Option<Vec<String>>,
    pub label: String,
    pub value_type: ScalarValueType,
    pub required: bool,
}
fn deserialize_claim_path<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error> {
    Vec::<String>::deserialize(deserializer).map(Some)
}
impl ScalarClaim {
    pub fn full_path(&self) -> Vec<String> {
        self.path
            .clone()
            .unwrap_or_else(|| vec!["credentialSubject".into(), self.name.clone()])
    }
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
    Object,
    Array,
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
fn claim_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        && !RESERVED.contains(&name.to_ascii_lowercase().as_str())
}
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
        let path = claim.full_path();
        if !claim_name(&claim.name)
            || !label(&claim.label)
            || path.len() < 2
            || path.len() > 16
            || path[0] != "credentialSubject"
            || path.last() != Some(&claim.name)
            || path[1..].iter().any(|component| !claim_name(component))
            || claims
                .iter()
                .any(|other: &Vec<String>| path.starts_with(other) || other.starts_with(&path))
        {
            return Err(invalid(
                "invalid, reserved, duplicate or overlapping claim path",
            ));
        }
        claims.insert(path);
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
            if !claims.contains(path) || !paths.insert(path) {
                return Err(invalid(
                    "disclosure path must name one unique declared claim",
                ));
            }
        }
    }
    if serde_json::to_vec(definition)
        .map_err(|_| invalid("definition cannot be serialized"))?
        .len()
        > 131_072
    {
        return Err(invalid("definition exceeds the serialized byte limit"));
    }
    Ok(())
}
pub fn validate_scalar_subject(
    definition: &ScalarCredentialDefinition,
    subject: &Value,
    mode: SubjectValidationMode,
) -> CoreResult<()> {
    validate_scalar_definition(definition)?;
    if !subject.is_object() {
        return Err(invalid("subject must be an object"));
    }
    let mut nodes = 0;
    validate_value_bounds(subject, 1, &mut nodes)?;
    if serde_json::to_vec(subject)
        .map_err(|_| invalid("subject cannot be serialized"))?
        .len()
        > 65_536
    {
        return Err(invalid("subject exceeds the total serialized byte limit"));
    }
    validate_subject_branch(definition, subject, &["credentialSubject".into()])?;
    if mode == SubjectValidationMode::Complete {
        for claim in &definition.claims {
            if claim.required && subject_value(subject, &claim.full_path()[1..]).is_none() {
                return Err(invalid("required claim path is missing"));
            }
        }
    }
    Ok(())
}
fn validate_value_bounds(value: &Value, depth: usize, nodes: &mut usize) -> CoreResult<()> {
    *nodes += 1;
    if depth > 16 || *nodes > 1024 {
        return Err(invalid("subject exceeds total depth or value node limit"));
    }
    match value {
        Value::Object(object) => {
            if object.len() > 64 {
                return Err(invalid("object exceeds immediate entry limit"));
            }
            for (name, child) in object {
                if !claim_name(name) {
                    return Err(invalid("invalid or reserved object property"));
                }
                validate_value_bounds(child, depth + 1, nodes)?;
            }
        }
        Value::Array(array) => {
            if array.len() > 64 {
                return Err(invalid("array exceeds immediate entry limit"));
            }
            for child in array {
                validate_value_bounds(child, depth + 1, nodes)?;
            }
        }
        Value::String(text) if text.len() <= 1024 => {}
        Value::Number(number)
            if number.as_f64().is_some_and(|value| {
                value.is_finite() && value.abs() <= 9_007_199_254_740_991.0
            }) => {}
        Value::Bool(_) => {}
        _ => {
            return Err(invalid(
                "unsupported or out-of-bounds structured scalar value",
            ));
        }
    }
    Ok(())
}
fn subject_value<'a>(mut value: &'a Value, path: &[String]) -> Option<&'a Value> {
    for component in path {
        value = value.as_object()?.get(component)?;
    }
    Some(value)
}
/// Remove authenticated SD-JWT bookkeeping only from structural path containers.
/// A declared whole value remains untouched, so partial values cannot pass as complete ones.
pub(crate) fn remove_structural_sd_metadata(
    definition: &ScalarCredentialDefinition,
    value: &mut Value,
    path: &mut Vec<String>,
) {
    if definition
        .claims
        .iter()
        .any(|claim| claim.full_path() == *path)
        || !definition
            .claims
            .iter()
            .any(|claim| claim.full_path().starts_with(path))
    {
        return;
    }
    if let Some(object) = value.as_object_mut() {
        object.remove("_sd");
        for (name, child) in object {
            path.push(name.clone());
            remove_structural_sd_metadata(definition, child, path);
            path.pop();
        }
    }
}
fn validate_subject_branch(
    definition: &ScalarCredentialDefinition,
    value: &Value,
    path: &[String],
) -> CoreResult<()> {
    if let Some(claim) = definition
        .claims
        .iter()
        .find(|claim| claim.full_path() == path)
    {
        let valid = match claim.value_type {
            ScalarValueType::String => value.as_str().is_some_and(|value| value.len() <= 1024),
            ScalarValueType::Boolean => value.is_boolean(),
            ScalarValueType::Object => value.is_object(),
            ScalarValueType::Array => value.is_array(),
            ScalarValueType::Integer | ScalarValueType::Number => {
                value.as_f64().is_some_and(|number| {
                    number.is_finite()
                        && number.abs() <= 9_007_199_254_740_991.0
                        && (claim.value_type == ScalarValueType::Number || number.fract() == 0.0)
                })
            }
        };
        return if valid {
            Ok(())
        } else {
            Err(invalid(
                "claim value does not match its declared type or bounds",
            ))
        };
    }
    if !definition
        .claims
        .iter()
        .any(|claim| claim.full_path().starts_with(path))
    {
        return Err(invalid("undeclared subject claim path"));
    }
    let object = value
        .as_object()
        .ok_or_else(|| invalid("claim path containers must be objects"))?;
    for (name, child) in object {
        let mut child_path = path.to_vec();
        child_path.push(name.clone());
        validate_subject_branch(definition, child, &child_path)?;
    }
    Ok(())
}
