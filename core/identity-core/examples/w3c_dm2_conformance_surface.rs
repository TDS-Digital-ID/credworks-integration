use std::{
    collections::HashMap,
    env,
    io::{self, Read},
};

use identity_core::{
    CoreError, CoreErrorCode, CoreResult, CredentialFormat, FixedSaltSource, JwsHeader, KeyId,
    PublicJwk, SdJwtCredentialVerificationOptions, Signer, b64_encode, issue_sd_jwt,
    validate_w3c_vc_data_model_presentation, verify_sd_jwt_credential,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use serde::Deserialize;
use serde_json::{Value, json};

const ISSUER_KEY_ID: &str = "urn:unsw-vc:w3c-dm2-suite:issuer";
const ISSUER_PRIVATE_SCALAR: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const ENVELOPE_PREFIX: &str = "data:application/vc+sd-jwt,";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueInput {
    credential: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyCredentialInput {
    #[serde(rename = "verifiableCredential")]
    verifiable_credential: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyPresentationInput {
    #[serde(rename = "verifiablePresentation")]
    verifiable_presentation: Value,
}

struct HarnessSigner {
    keys: HashMap<String, SigningKey>,
}

impl Signer for HarnessSigner {
    fn sign(&self, key_id: &KeyId, signing_input: &[u8]) -> CoreResult<Vec<u8>> {
        let signing_key = self.keys.get(key_id.as_str()).ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::KeyNotFound,
                "W3C suite key handle is unavailable",
            )
        })?;
        let signature: Signature = signing_key.sign(signing_input);
        Ok(signature.to_bytes().to_vec())
    }
}

fn main() {
    match run() {
        Ok(output) => println!(
            "{}",
            serde_json::to_string(&output).expect("output serializes")
        ),
        Err(error) => {
            println!(
                "{}",
                serde_json::to_string(&json!({"error_code": error.code()}))
                    .expect("error output serializes")
            );
            std::process::exit(2);
        }
    }
}

fn run() -> CoreResult<Value> {
    let command = env::args().nth(1).unwrap_or_default();
    let input = read_stdin().map_err(|_| {
        CoreError::new(
            CoreErrorCode::InvalidInput,
            "W3C suite input could not be read",
        )
    })?;
    match command.as_str() {
        "issue" => {
            let input: IssueInput = serde_json::from_str(&input).map_err(|_| {
                CoreError::new(
                    CoreErrorCode::InvalidInput,
                    "W3C suite issue input is malformed",
                )
            })?;
            issue(input.credential)
        }
        "verify-credential" => {
            let input: VerifyCredentialInput = serde_json::from_str(&input).map_err(|_| {
                CoreError::new(
                    CoreErrorCode::InvalidInput,
                    "W3C suite verifier input is malformed",
                )
            })?;
            verify_credential(&input.verifiable_credential)
        }
        "verify-presentation" => {
            let input: VerifyPresentationInput = serde_json::from_str(&input).map_err(|_| {
                CoreError::new(
                    CoreErrorCode::InvalidInput,
                    "W3C suite presentation input is malformed",
                )
            })?;
            validate_w3c_vc_data_model_presentation(&input.verifiable_presentation)?;
            Err(CoreError::new(
                CoreErrorCode::UnsupportedAlgorithm,
                "the W3C suite Data Integrity presentation is outside the primary SD-JWT profile",
            ))
        }
        _ => Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "unknown W3C conformance command",
        )),
    }
}

fn issue(credential: Value) -> CoreResult<Value> {
    let (signer, public_jwk) = signer()?;
    let mut salts = FixedSaltSource::new(std::iter::empty::<Vec<u8>>());
    let issued = issue_sd_jwt(
        credential,
        &[],
        0,
        &JwsHeader::es256(Some("vc+sd-jwt".to_owned()), Some(ISSUER_KEY_ID.to_owned())),
        &signer,
        &KeyId::new(ISSUER_KEY_ID),
        &mut salts,
    )?;
    Ok(json!({
        "verifiableCredential": {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": "EnvelopedVerifiableCredential",
            "id": format!("{ENVELOPE_PREFIX}{}", issued.compact)
        },
        "issuerPublicJwk": public_jwk
    }))
}

fn verify_credential(envelope: &Value) -> CoreResult<Value> {
    let compact = validate_and_extract_envelope(envelope)?;
    let (_, public_jwk) = signer()?;
    let verified = verify_sd_jwt_credential(
        compact,
        &public_jwk,
        &SdJwtCredentialVerificationOptions {
            now_unix_seconds: 1_800_000_000,
            required_claims: Vec::new(),
            format: CredentialFormat::W3cVcDataModel,
        },
    )?;
    Ok(json!({
        "checks": ["proof", "data_model"],
        "verified": true,
        "type": verified.processed_payload.get("type")
    }))
}

fn validate_and_extract_envelope(envelope: &Value) -> CoreResult<&str> {
    let object = envelope.as_object().ok_or_else(|| {
        CoreError::new(
            CoreErrorCode::InvalidInput,
            "enveloped credential must be an object",
        )
    })?;
    let context_is_valid = match object.get("@context") {
        Some(Value::String(value)) => value == "https://www.w3.org/ns/credentials/v2",
        Some(Value::Array(values)) => {
            values.first().and_then(Value::as_str) == Some("https://www.w3.org/ns/credentials/v2")
        }
        _ => false,
    };
    if !context_is_valid {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "enveloped credential context is invalid",
        ));
    }
    let has_envelope_type = match object.get("type") {
        Some(Value::String(value)) => value == "EnvelopedVerifiableCredential",
        Some(Value::Array(values)) => values
            .iter()
            .any(|value| value.as_str() == Some("EnvelopedVerifiableCredential")),
        _ => false,
    };
    if !has_envelope_type {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "enveloped credential type is invalid",
        ));
    }
    object
        .get("id")
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix(ENVELOPE_PREFIX))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::InvalidInput,
                "enveloped credential id must use the SD-JWT data URL media type",
            )
        })
}

fn signer() -> CoreResult<(HarnessSigner, PublicJwk)> {
    let signing_key = SigningKey::from_slice(&ISSUER_PRIVATE_SCALAR).map_err(|_| {
        CoreError::new(CoreErrorCode::InvalidKey, "W3C suite issuer key is invalid")
    })?;
    let point = signing_key.verifying_key().to_sec1_point(false);
    let public_jwk = PublicJwk::p256(
        b64_encode(point.x().expect("uncompressed P-256 point has x")),
        b64_encode(point.y().expect("uncompressed P-256 point has y")),
        Some(ISSUER_KEY_ID.to_owned()),
    );
    Ok((
        HarnessSigner {
            keys: HashMap::from([(ISSUER_KEY_ID.to_owned(), signing_key)]),
        },
        public_jwk,
    ))
}

fn read_stdin() -> io::Result<String> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    Ok(input)
}
