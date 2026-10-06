use std::{
    collections::HashMap,
    env,
    io::{self, Read},
};

use identity_core::{
    DisclosureProfile, DisclosureSpec, FixedSaltSource, JwsHeader, KeyId, PublicJwk,
    SdJwtVerificationOptions, Signer, b64_encode, issue_sd_jwt, present_sd_jwt,
    verify_sd_jwt_presentation,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use serde::Deserialize;
use serde_json::{Value, json};

const TEST_ISSUER_PRIVATE_SCALAR: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const TEST_HOLDER_PRIVATE_SCALAR: [u8; 32] = [
    0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10,
    0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x01,
];

#[derive(Debug, Deserialize)]
struct IssueInput {
    issuer_key_id: String,
    holder_key_id: String,
    audience: String,
    nonce: String,
    issued_at: i64,
    payload: Value,
    disclosure_specs: Vec<DisclosureSpec>,
    salts: Vec<String>,
    profile: DisclosureProfile,
}

#[derive(Debug, Deserialize)]
struct VerifyBatchInput {
    issuer_jwk: PublicJwk,
    options: SdJwtVerificationOptions,
    presentations: Vec<PresentationInput>,
}

#[derive(Debug, Deserialize)]
struct PresentationInput {
    surface: String,
    presentation: String,
}

struct HarnessSigner {
    keys: HashMap<String, SigningKey>,
}

impl Signer for HarnessSigner {
    fn sign(&self, key_id: &KeyId, signing_input: &[u8]) -> identity_core::CoreResult<Vec<u8>> {
        let signing_key = self.keys.get(key_id.as_str()).ok_or_else(|| {
            identity_core::CoreError::new(
                identity_core::CoreErrorCode::KeyNotFound,
                format!("rust conformance key not found: {}", key_id.as_str()),
            )
        })?;
        let signature: Signature = signing_key.sign(signing_input);
        Ok(signature.to_bytes().to_vec())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let command = env::args().nth(1).unwrap_or_default();
    match command.as_str() {
        "issue" => issue(),
        "verify-batch" => verify_batch(),
        _ => Err(format!("unknown conformance command: {command}").into()),
    }
}

fn issue() -> Result<(), Box<dyn std::error::Error>> {
    let input: IssueInput = serde_json::from_str(&read_stdin()?)?;
    let mut payload = input.payload;
    let issuer_key = SigningKey::from_slice(&TEST_ISSUER_PRIVATE_SCALAR)?;
    let holder_key = SigningKey::from_slice(&TEST_HOLDER_PRIVATE_SCALAR)?;
    let issuer_jwk = public_jwk_from_signing_key(&issuer_key, Some(input.issuer_key_id.clone()));
    let holder_jwk = public_jwk_from_signing_key(&holder_key, Some(input.holder_key_id.clone()));
    payload["cnf"]["jwk"] = serde_json::to_value(&holder_jwk)?;

    let signer = HarnessSigner {
        keys: HashMap::from([
            (input.issuer_key_id.clone(), issuer_key),
            (input.holder_key_id.clone(), holder_key),
        ]),
    };
    let mut salt_source = FixedSaltSource::new(
        input
            .salts
            .iter()
            .map(|salt| identity_core::b64_decode(salt))
            .collect::<identity_core::CoreResult<Vec<_>>>()?,
    );
    let issued = issue_sd_jwt(
        payload,
        &input.disclosure_specs,
        0,
        &JwsHeader::es256(
            Some("vc+sd-jwt".to_owned()),
            Some(input.issuer_key_id.clone()),
        ),
        &signer,
        &KeyId::new(input.issuer_key_id),
        &mut salt_source,
    )?;
    let presentation = present_sd_jwt(
        &issued.compact,
        &input.profile,
        &signer,
        &KeyId::new(input.holder_key_id),
        input.audience,
        input.nonce,
        input.issued_at,
    )?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "issuer_jwk": issuer_jwk,
            "holder_jwk": holder_jwk,
            "issued": issued,
            "presentation": presentation
        }))?
    );
    Ok(())
}

fn verify_batch() -> Result<(), Box<dyn std::error::Error>> {
    let input: VerifyBatchInput = serde_json::from_str(&read_stdin()?)?;
    let mut results = Vec::new();
    for item in input.presentations {
        let verified =
            verify_sd_jwt_presentation(&item.presentation, &input.issuer_jwk, &input.options)?;
        results.push(json!({
            "surface": item.surface,
            "processed_payload": verified.processed_payload
        }));
    }
    println!("{}", serde_json::to_string(&results)?);
    Ok(())
}

fn read_stdin() -> Result<String, io::Error> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    Ok(input)
}

fn public_jwk_from_signing_key(signing_key: &SigningKey, kid: Option<String>) -> PublicJwk {
    let point = signing_key.verifying_key().to_sec1_point(false);
    let x = point.x().expect("uncompressed P-256 point has x");
    let y = point.y().expect("uncompressed P-256 point has y");
    PublicJwk::p256(b64_encode(x), b64_encode(y), kid)
}
