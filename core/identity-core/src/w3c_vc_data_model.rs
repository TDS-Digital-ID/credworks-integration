use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;

use crate::{CoreError, CoreErrorCode, CoreResult};

const BASE_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";
const VC_TYPE: &str = "VerifiableCredential";
const VP_TYPE: &str = "VerifiablePresentation";
// The terms protected at the top level of the VC v2 base context. Scoped
// contexts are activated by their defining type and must not be flattened into
// this set: for example, `holder` is protected for presentations but can be
// defined independently by a credential context.
const BASE_GLOBAL_PROTECTED_TERMS: &[&str] = &[
    "...",
    "BitstringStatusList",
    "BitstringStatusListCredential",
    "BitstringStatusListEntry",
    "DataIntegrityProof",
    "EnvelopedVerifiableCredential",
    "EnvelopedVerifiablePresentation",
    "JsonSchema",
    "JsonSchemaCredential",
    "VerifiableCredential",
    "VerifiablePresentation",
    "_sd",
    "_sd_alg",
    "aud",
    "cnf",
    "description",
    "digestMultibase",
    "digestSRI",
    "exp",
    "iat",
    "id",
    "iss",
    "jku",
    "kid",
    "mediaType",
    "name",
    "nbf",
    "sub",
    "type",
    "x5u",
];

const VC_SCOPED_PROTECTED_TERMS: &[&str] = &[
    "id",
    "type",
    "confidenceMethod",
    "credentialSchema",
    "credentialStatus",
    "credentialSubject",
    "description",
    "evidence",
    "issuer",
    "name",
    "proof",
    "refreshService",
    "relatedResource",
    "renderMethod",
    "termsOfUse",
    "validFrom",
    "validUntil",
];

const VP_SCOPED_PROTECTED_TERMS: &[&str] = &[
    "id",
    "type",
    "holder",
    "proof",
    "termsOfUse",
    "verifiableCredential",
];

/// Validate the observable W3C Verifiable Credentials Data Model 2.0 document
/// requirements used by the ecosystem's `vc+sd-jwt` profile.
///
/// This validates the compacted JSON-LD document before it is secured and
/// after an SD-JWT credential is verified. It deliberately does not resolve
/// contexts, schemas, status lists, or related resources; those operations
/// remain behind the core's injected resolver ports.
pub fn validate_w3c_vc_data_model_credential(document: &Value) -> CoreResult<()> {
    let object = require_object(document, "credential")?;
    let contexts = ContextTerms::parse(object.get("@context"), VC_SCOPED_PROTECTED_TERMS)?;
    validate_types(object.get("type"), VC_TYPE, &contexts, "credential.type")?;
    optional_url(object.get("id"), "credential.id")?;

    let issuer = object
        .get("issuer")
        .ok_or_else(|| invalid("credential.issuer is required"))?;
    validate_issuer(issuer)?;

    let subjects = object
        .get("credentialSubject")
        .ok_or_else(|| invalid("credential.credentialSubject is required"))?;
    for (index, subject) in one_or_more_objects(subjects, "credential.credentialSubject")?
        .into_iter()
        .enumerate()
    {
        if subject.is_empty() {
            return Err(invalid(format!(
                "credential.credentialSubject[{index}] must contain at least one claim"
            )));
        }
        optional_url(
            subject.get("id"),
            &format!("credential.credentialSubject[{index}].id"),
        )?;
    }

    optional_language_values(object.get("name"), "credential.name")?;
    optional_language_values(object.get("description"), "credential.description")?;
    optional_timestamp(object.get("validFrom"), "credential.validFrom")?;
    optional_timestamp(object.get("validUntil"), "credential.validUntil")?;
    validate_validity_order(object)?;

    validate_typed_objects(
        object.get("credentialStatus"),
        "credential.credentialStatus",
        &contexts,
        false,
    )?;
    validate_typed_objects(
        object.get("credentialSchema"),
        "credential.credentialSchema",
        &contexts,
        true,
    )?;
    validate_typed_objects(
        object.get("refreshService"),
        "credential.refreshService",
        &contexts,
        false,
    )?;
    validate_typed_objects(
        object.get("termsOfUse"),
        "credential.termsOfUse",
        &contexts,
        false,
    )?;
    validate_typed_objects(
        object.get("evidence"),
        "credential.evidence",
        &contexts,
        false,
    )?;
    validate_typed_objects(
        object.get("confidenceMethod"),
        "credential.confidenceMethod",
        &contexts,
        false,
    )?;
    validate_typed_objects(
        object.get("renderMethod"),
        "credential.renderMethod",
        &contexts,
        false,
    )?;
    validate_related_resources(object.get("relatedResource"))?;

    Ok(())
}

/// Validate the data-model shape of a W3C Verifiable Presentation 2.0.
///
/// Securing-mechanism verification is a separate operation. In particular,
/// this function does not accept an embedded Data Integrity proof as verified.
pub fn validate_w3c_vc_data_model_presentation(document: &Value) -> CoreResult<()> {
    let object = require_object(document, "presentation")?;
    let contexts = ContextTerms::parse(object.get("@context"), VP_SCOPED_PROTECTED_TERMS)?;
    validate_types(object.get("type"), VP_TYPE, &contexts, "presentation.type")?;
    optional_url(object.get("id"), "presentation.id")?;
    if let Some(holder) = object.get("holder") {
        match holder {
            Value::String(value) => require_url(value, "presentation.holder")?,
            Value::Object(holder) => {
                let id = holder
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("presentation.holder.id must be a URL string"))?;
                require_url(id, "presentation.holder.id")?;
            }
            _ => {
                return Err(invalid(
                    "presentation.holder must be a URL or object with id",
                ));
            }
        }
    }
    if let Some(credentials) = object.get("verifiableCredential") {
        let values = match credentials {
            Value::Array(values) if !values.is_empty() => values.as_slice(),
            Value::Object(_) => std::slice::from_ref(credentials),
            _ => {
                return Err(invalid(
                    "presentation.verifiableCredential must contain one or more objects",
                ));
            }
        };
        if values.iter().any(|value| !value.is_object()) {
            return Err(invalid(
                "presentation.verifiableCredential values must be objects",
            ));
        }
    }
    validate_typed_objects(
        object.get("confidenceMethod"),
        "presentation.confidenceMethod",
        &contexts,
        false,
    )?;
    validate_typed_objects(
        object.get("renderMethod"),
        "presentation.renderMethod",
        &contexts,
        false,
    )?;
    Ok(())
}

fn validate_issuer(value: &Value) -> CoreResult<()> {
    match value {
        Value::String(issuer) => require_url(issuer, "credential.issuer"),
        Value::Object(issuer) => {
            let id = issuer
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("credential.issuer.id must be a URL string"))?;
            require_url(id, "credential.issuer.id")?;
            optional_language_values(issuer.get("name"), "credential.issuer.name")?;
            optional_language_values(issuer.get("description"), "credential.issuer.description")
        }
        _ => Err(invalid("credential.issuer must be a URL or object with id")),
    }
}

fn validate_validity_order(object: &Map<String, Value>) -> CoreResult<()> {
    let (Some(valid_from), Some(valid_until)) = (
        object.get("validFrom").and_then(Value::as_str),
        object.get("validUntil").and_then(Value::as_str),
    ) else {
        return Ok(());
    };
    let from = parse_timestamp(valid_from, "credential.validFrom")?;
    let until = parse_timestamp(valid_until, "credential.validUntil")?;
    if from > until {
        return Err(invalid(
            "credential.validFrom must not be later than credential.validUntil",
        ));
    }
    Ok(())
}

fn validate_typed_objects(
    value: Option<&Value>,
    path: &str,
    contexts: &ContextTerms,
    require_id: bool,
) -> CoreResult<()> {
    let Some(value) = value else {
        return Ok(());
    };
    for (index, object) in one_or_more_objects(value, path)?.into_iter().enumerate() {
        validate_type_values(
            object
                .get("type")
                .ok_or_else(|| invalid(format!("{path}[{index}].type is required")))?,
            contexts,
            &format!("{path}[{index}].type"),
        )?;
        if require_id && !object.contains_key("id") {
            return Err(invalid(format!("{path}[{index}].id is required")));
        }
        optional_url(object.get("id"), &format!("{path}[{index}].id"))?;
    }
    Ok(())
}

fn validate_related_resources(value: Option<&Value>) -> CoreResult<()> {
    let Some(value) = value else {
        return Ok(());
    };
    let resources = one_or_more_objects(value, "credential.relatedResource")?;
    let mut ids = HashSet::new();
    for (index, resource) in resources.into_iter().enumerate() {
        let id = resource.get("id").and_then(Value::as_str).ok_or_else(|| {
            invalid(format!(
                "credential.relatedResource[{index}].id is required"
            ))
        })?;
        require_url(id, &format!("credential.relatedResource[{index}].id"))?;
        if !ids.insert(id) {
            return Err(invalid("credential.relatedResource ids must be unique"));
        }
        if !resource.get("digestSRI").is_some_and(Value::is_string)
            && !resource
                .get("digestMultibase")
                .is_some_and(Value::is_string)
        {
            return Err(invalid(format!(
                "credential.relatedResource[{index}] requires digestSRI or digestMultibase"
            )));
        }
        if resource
            .get("mediaType")
            .is_some_and(|value| !value.is_string())
        {
            return Err(invalid(format!(
                "credential.relatedResource[{index}].mediaType must be a string"
            )));
        }
    }
    Ok(())
}

fn validate_types(
    value: Option<&Value>,
    required: &str,
    contexts: &ContextTerms,
    path: &str,
) -> CoreResult<()> {
    let value = value.ok_or_else(|| invalid(format!("{path} is required")))?;
    let values = validate_type_values(value, contexts, path)?;
    if !values.contains(&required) {
        return Err(invalid(format!("{path} must include {required}")));
    }
    Ok(())
}

fn validate_type_values<'a>(
    value: &'a Value,
    contexts: &ContextTerms,
    path: &str,
) -> CoreResult<Vec<&'a str>> {
    let values = match value {
        Value::String(_) => std::slice::from_ref(value),
        Value::Array(values) if !values.is_empty() => values.as_slice(),
        _ => return Err(invalid(format!("{path} must contain one or more strings"))),
    };
    let mut result = Vec::with_capacity(values.len());
    for item in values {
        let item = item
            .as_str()
            .ok_or_else(|| invalid(format!("{path} values must be strings")))?;
        if !contexts.expands_term(item) {
            return Err(invalid(format!("{path} contains an unmapped term")));
        }
        result.push(item);
    }
    Ok(result)
}

fn optional_language_values(value: Option<&Value>, path: &str) -> CoreResult<()> {
    let Some(value) = value else {
        return Ok(());
    };
    match value {
        Value::String(_) => Ok(()),
        Value::Object(object) => validate_language_value(object, path),
        Value::Array(values) if !values.is_empty() => {
            for (index, value) in values.iter().enumerate() {
                let object = value
                    .as_object()
                    .ok_or_else(|| invalid(format!("{path}[{index}] must be a language object")))?;
                validate_language_value(object, &format!("{path}[{index}]"))?;
            }
            Ok(())
        }
        _ => Err(invalid(format!(
            "{path} must be a string or one or more language objects"
        ))),
    }
}

fn validate_language_value(object: &Map<String, Value>, path: &str) -> CoreResult<()> {
    if !object.get("@value").is_some_and(Value::is_string)
        || object
            .get("@language")
            .is_some_and(|value| !value.is_string())
        || object
            .get("@direction")
            .is_some_and(|value| !matches!(value.as_str(), Some("ltr" | "rtl")))
        || object
            .keys()
            .any(|key| !matches!(key.as_str(), "@value" | "@language" | "@direction"))
    {
        return Err(invalid(format!("{path} is not a valid language value")));
    }
    Ok(())
}

fn optional_timestamp(value: Option<&Value>, path: &str) -> CoreResult<()> {
    let Some(value) = value else {
        return Ok(());
    };
    let value = value
        .as_str()
        .ok_or_else(|| invalid(format!("{path} must be a dateTimeStamp string")))?;
    parse_timestamp(value, path).map(|_| ())
}

fn parse_timestamp(value: &str, path: &str) -> CoreResult<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| invalid(format!("{path} must be a valid RFC 3339 dateTimeStamp")))
}

fn optional_url(value: Option<&Value>, path: &str) -> CoreResult<()> {
    let Some(value) = value else {
        return Ok(());
    };
    let value = value
        .as_str()
        .ok_or_else(|| invalid(format!("{path} must be a single URL string")))?;
    require_url(value, path)
}

fn require_url(value: &str, path: &str) -> CoreResult<()> {
    let parsed = Url::parse(value).map_err(|_| invalid(format!("{path} must be a URL")))?;
    if parsed.scheme().is_empty() {
        return Err(invalid(format!("{path} must be an absolute URL")));
    }
    Ok(())
}

fn require_object<'a>(value: &'a Value, path: &str) -> CoreResult<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| invalid(format!("{path} must be a JSON object")))
}

fn one_or_more_objects<'a>(
    value: &'a Value,
    path: &str,
) -> CoreResult<Vec<&'a Map<String, Value>>> {
    match value {
        Value::Object(object) => Ok(vec![object]),
        Value::Array(values) if !values.is_empty() => values
            .iter()
            .map(|value| {
                value
                    .as_object()
                    .ok_or_else(|| invalid(format!("{path} values must be objects")))
            })
            .collect(),
        _ => Err(invalid(format!("{path} must contain one or more objects"))),
    }
}

#[derive(Default)]
struct ContextTerms {
    mappings: HashMap<String, Option<String>>,
    protected_terms: HashSet<String>,
    default_vocab_enabled: bool,
}

impl ContextTerms {
    fn parse(value: Option<&Value>, scoped_protected_terms: &[&str]) -> CoreResult<Self> {
        let contexts = value
            .and_then(Value::as_array)
            .filter(|contexts| !contexts.is_empty())
            .ok_or_else(|| invalid("credential @context must be a non-empty ordered set"))?;
        if contexts.first().and_then(Value::as_str) != Some(BASE_CONTEXT) {
            return Err(invalid(format!(
                "credential @context must begin with {BASE_CONTEXT}"
            )));
        }
        let mut result = Self {
            default_vocab_enabled: true,
            ..Self::default()
        };
        result.protected_terms.extend(
            BASE_GLOBAL_PROTECTED_TERMS
                .iter()
                .map(|term| (*term).to_owned()),
        );
        result
            .protected_terms
            .extend(scoped_protected_terms.iter().map(|term| (*term).to_owned()));
        for context in contexts.iter().skip(1) {
            match context {
                Value::String(value) => require_url(value, "credential @context item")?,
                Value::Object(object) => result.apply_object(object)?,
                _ => {
                    return Err(invalid(
                        "credential @context items must be URLs or JSON-LD context objects",
                    ));
                }
            }
        }
        Ok(result)
    }

    fn apply_object(&mut self, object: &Map<String, Value>) -> CoreResult<()> {
        let protect_new_terms = object
            .get("@protected")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        for (term, definition) in object {
            if term == "@protected" {
                continue;
            }
            if term == "@vocab" {
                match definition {
                    Value::Null => self.default_vocab_enabled = false,
                    Value::String(value) => {
                        require_url(value, "@context @vocab")?;
                        self.default_vocab_enabled = true;
                    }
                    _ => return Err(invalid("@context @vocab must be a URL or null")),
                }
                continue;
            }
            if self.protected_terms.contains(term) && self.mappings.contains_key(term) {
                return Err(invalid("a protected JSON-LD context term was redefined"));
            }
            if self.protected_terms.contains(term) {
                return Err(invalid("the base JSON-LD context term was redefined"));
            }
            let mapping = match definition {
                Value::Null => None,
                Value::String(value) => {
                    require_url(value, &format!("@context term {term}"))?;
                    Some(value.clone())
                }
                Value::Object(definition) => {
                    let id = definition
                        .get("@id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| invalid(format!("@context term {term} requires @id")))?;
                    require_url(id, &format!("@context term {term} @id"))?;
                    Some(id.to_owned())
                }
                _ => return Err(invalid(format!("@context term {term} is not processable"))),
            };
            self.mappings.insert(term.clone(), mapping);
            if protect_new_terms {
                self.protected_terms.insert(term.clone());
            }
        }
        Ok(())
    }

    fn expands_term(&self, term: &str) -> bool {
        if Url::parse(term).is_ok() {
            return true;
        }
        match self.mappings.get(term) {
            Some(Some(_)) => true,
            Some(None) => false,
            None => self.default_vocab_enabled,
        }
    }
}

fn invalid(message: impl Into<String>) -> CoreError {
    CoreError::new(CoreErrorCode::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn credential() -> Value {
        json!({
            "@context": [BASE_CONTEXT],
            "type": [VC_TYPE, "UniversityEducationCredential"],
            "issuer": "did:web:issuer.unsw.example",
            "validFrom": "2026-07-01T00:00:00Z",
            "validUntil": "2027-07-01T00:00:00Z",
            "credentialSubject": {"institution_id": "unsw.edu.au"}
        })
    }

    #[test]
    fn accepts_constitutional_w3c_credential_shape() {
        validate_w3c_vc_data_model_credential(&credential()).unwrap();
    }

    #[test]
    fn rejects_missing_required_properties_with_stable_code() {
        for property in ["@context", "type", "issuer", "credentialSubject"] {
            let mut value = credential();
            value.as_object_mut().unwrap().remove(property);
            assert_eq!(
                validate_w3c_vc_data_model_credential(&value)
                    .unwrap_err()
                    .code(),
                CoreErrorCode::InvalidInput
            );
        }
    }

    #[test]
    fn rejects_invalid_urls_types_subjects_and_dates() {
        for mutate in [
            |value: &mut Value| value["issuer"] = json!("not a url"),
            |value: &mut Value| value["id"] = json!(["did:example:one"]),
            |value: &mut Value| value["type"] = json!([VC_TYPE, 7]),
            |value: &mut Value| value["credentialSubject"] = json!({}),
            |value: &mut Value| value["validFrom"] = json!("2026-07-01"),
            |value: &mut Value| value["validUntil"] = json!("2025-01-01T00:00:00Z"),
        ] {
            let mut value = credential();
            mutate(&mut value);
            assert_eq!(
                validate_w3c_vc_data_model_credential(&value)
                    .unwrap_err()
                    .code(),
                CoreErrorCode::InvalidInput
            );
        }
    }

    #[test]
    fn validates_typed_objects_language_values_and_related_resources() {
        let mut value = credential();
        value["@context"] = json!([
            BASE_CONTEXT,
            {"ExampleStatus": "https://example.org/status#ExampleStatus"}
        ]);
        value["credentialStatus"] = json!({"type": "ExampleStatus", "id": "did:example:status"});
        value["confidenceMethod"] = json!({"type": "ExampleStatus"});
        value["renderMethod"] = json!({"type": "ExampleStatus"});
        value["name"] = json!({"@value": "Example", "@language": "en", "@direction": "ltr"});
        value["relatedResource"] = json!({
            "id": "https://example.org/context",
            "digestSRI": "sha384-example"
        });
        validate_w3c_vc_data_model_credential(&value).unwrap();

        value["name"]["extra"] = json!(true);
        assert_eq!(
            validate_w3c_vc_data_model_credential(&value)
                .unwrap_err()
                .code(),
            CoreErrorCode::InvalidInput
        );

        let mut reserved = credential();
        reserved["confidenceMethod"] = json!({"id": "did:example:confidence"});
        assert_eq!(
            validate_w3c_vc_data_model_credential(&reserved)
                .unwrap_err()
                .code(),
            CoreErrorCode::InvalidInput
        );
    }

    #[test]
    fn rejects_protected_context_redefinitions() {
        let mut value = credential();
        value["@context"] = json!([
            BASE_CONTEXT,
            {"@protected": true, "ExampleCredential": "https://example.org/one"},
            {"ExampleCredential": "https://example.org/two"}
        ]);
        assert_eq!(
            validate_w3c_vc_data_model_credential(&value)
                .unwrap_err()
                .code(),
            CoreErrorCode::InvalidInput
        );

        let mut base_term = credential();
        base_term["@context"] = json!([
            BASE_CONTEXT,
            {"credentialStatus": "https://example.org/redefined-status"}
        ]);
        assert_eq!(
            validate_w3c_vc_data_model_credential(&base_term)
                .unwrap_err()
                .code(),
            CoreErrorCode::InvalidInput
        );

        let mut presentation_scoped_term = credential();
        presentation_scoped_term["@context"] = json!([
            BASE_CONTEXT,
            {"holder": "https://example.org/holder"}
        ]);
        validate_w3c_vc_data_model_credential(&presentation_scoped_term).unwrap();
    }

    #[test]
    fn presentation_validation_is_structural_only() {
        let presentation = json!({
            "@context": [BASE_CONTEXT],
            "type": [VP_TYPE],
            "holder": "did:example:holder",
            "verifiableCredential": [{"type": "EnvelopedVerifiableCredential"}]
        });
        validate_w3c_vc_data_model_presentation(&presentation).unwrap();

        let mut invalid = presentation;
        invalid["verifiableCredential"] = json!(["compact-token"]);
        assert_eq!(
            validate_w3c_vc_data_model_presentation(&invalid)
                .unwrap_err()
                .code(),
            CoreErrorCode::InvalidInput
        );
    }
}
