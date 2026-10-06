use std::{
    collections::HashMap,
    env, fs,
    time::{SystemTime, UNIX_EPOCH},
};

use identity_core::{
    CoreError, CoreErrorCode, CoreResult, CredentialFormat, DisclosureSpec, JwsHeader, KeyId,
    OsSaltSource, PublicJwk, SdJwtCredentialVerificationOptions, Signer, b64_decode, b64_encode,
    issue_sd_jwt, verify_sd_jwt_credential,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use serde::Deserialize;
use serde_json::{Value, json};

const FEATURE: &str = "credential_sdjwt";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerificationMethod {
    id: String,
    #[serde(rename = "type")]
    type_: String,
    controller: String,
    public_key_jwk: SuitePublicJwk,
    #[serde(default)]
    secret_key_jwk: Option<SuitePrivateJwk>,
}

#[derive(Deserialize)]
struct SuitePublicJwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Deserialize)]
struct SuitePrivateJwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
    d: String,
}

struct HarnessSigner {
    keys: HashMap<String, SigningKey>,
}

impl Signer for HarnessSigner {
    fn sign(&self, key_id: &KeyId, signing_input: &[u8]) -> CoreResult<Vec<u8>> {
        let key = self.keys.get(key_id.as_str()).ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::KeyNotFound,
                "VC JOSE/COSE conformance key handle is unavailable",
            )
        })?;
        let signature: Signature = key.sign(signing_input);
        Ok(signature.to_bytes().to_vec())
    }
}

fn main() {
    let output_path = argument("--output");
    let result =
        run().unwrap_or_else(|error| json!({"result": "failure", "error_code": error.code()}));
    let serialized = serde_json::to_vec(&result).expect("conformance result serializes");
    if let Some(path) = output_path {
        if fs::write(path, serialized).is_err() {
            std::process::exit(2);
        }
    } else {
        println!("{}", String::from_utf8_lossy(&serialized));
    }
}

fn run() -> CoreResult<Value> {
    let command = env::args().nth(1).unwrap_or_default();
    if argument("--feature").as_deref() != Some(FEATURE) {
        return Ok(json!({"result": "indeterminate"}));
    }
    let input_path = required_argument("--input")?;
    let key_path = required_argument("--key")?;
    let verification_method: VerificationMethod = read_json(&key_path)?;
    ensure_verification_method(&verification_method)?;
    ensure_p256(&verification_method.public_key_jwk)?;

    match command.as_str() {
        "issue" => issue(&input_path, &verification_method),
        "verify" => verify(&input_path, &verification_method),
        _ => Ok(json!({"result": "indeterminate"})),
    }
}

fn issue(input_path: &str, verification_method: &VerificationMethod) -> CoreResult<Value> {
    let credential: Value = read_json(input_path)?;
    let secret = verification_method.secret_key_jwk.as_ref().ok_or_else(|| {
        CoreError::new(
            CoreErrorCode::InvalidKey,
            "VC JOSE/COSE issuance fixture has no private key",
        )
    })?;
    ensure_private_p256(secret, &verification_method.public_key_jwk)?;
    let signing_key = SigningKey::from_slice(&b64_decode(&secret.d)?).map_err(|_| {
        CoreError::new(
            CoreErrorCode::InvalidKey,
            "VC JOSE/COSE P-256 private key is invalid",
        )
    })?;
    ensure_key_pair(&signing_key, &verification_method.public_key_jwk)?;
    let key_id = KeyId::new(verification_method.id.clone());
    let signer = HarnessSigner {
        keys: HashMap::from([(verification_method.id.clone(), signing_key)]),
    };
    let disclosures = disclosure_specs(argument("--sd").as_deref())?;
    let mut salt_source = OsSaltSource;
    let issued = issue_sd_jwt(
        credential,
        &disclosures,
        0,
        &JwsHeader {
            alg: "ES256".to_owned(),
            typ: Some("vc+sd-jwt".to_owned()),
            cty: Some("vc".to_owned()),
            kid: Some(verification_method.id.clone()),
            jwk: None,
            x5c: None,
        },
        &signer,
        &key_id,
        &mut salt_source,
    )?;
    Ok(json!({"result": "success", "data": issued.compact}))
}

fn verify(input_path: &str, verification_method: &VerificationMethod) -> CoreResult<Value> {
    let compact = fs::read_to_string(input_path).map_err(|_| {
        CoreError::new(
            CoreErrorCode::InvalidInput,
            "VC JOSE/COSE credential fixture could not be read",
        )
    })?;
    let public_jwk = public_jwk(&verification_method.public_key_jwk);
    let now_unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CoreError::new(CoreErrorCode::InvalidInput, "system clock is invalid"))?
        .as_secs() as i64;
    verify_sd_jwt_credential(
        compact.trim(),
        &public_jwk,
        &SdJwtCredentialVerificationOptions {
            now_unix_seconds,
            required_claims: Vec::new(),
            format: CredentialFormat::W3cVcDataModel,
        },
    )?;
    Ok(json!({"result": "success"}))
}

fn disclosure_specs(encoded: Option<&str>) -> CoreResult<Vec<DisclosureSpec>> {
    let paths: Vec<String> = match encoded {
        Some(value) => serde_json::from_str(value).map_err(|_| {
            CoreError::new(
                CoreErrorCode::InvalidInput,
                "VC JOSE/COSE disclosure paths are malformed",
            )
        })?,
        None => Vec::new(),
    };
    paths
        .into_iter()
        .map(|path| {
            if path.contains('[') || path.contains(']') {
                return Err(CoreError::new(
                    CoreErrorCode::UnsupportedAlgorithm,
                    "array disclosure issuance is outside the conformance adapter",
                ));
            }
            let mut components = path.split('.').map(str::to_owned).collect::<Vec<_>>();
            let claim_name = components
                .pop()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    CoreError::new(
                        CoreErrorCode::InvalidInput,
                        "VC JOSE/COSE disclosure path is empty",
                    )
                })?;
            if components.iter().any(String::is_empty) {
                return Err(CoreError::new(
                    CoreErrorCode::InvalidInput,
                    "VC JOSE/COSE disclosure path has an empty component",
                ));
            }
            Ok(DisclosureSpec {
                object_path: components,
                claim_name,
            })
        })
        .collect()
}

fn public_jwk(jwk: &SuitePublicJwk) -> PublicJwk {
    PublicJwk::p256(jwk.x.clone(), jwk.y.clone(), jwk.kid.clone())
}

fn ensure_p256(jwk: &SuitePublicJwk) -> CoreResult<()> {
    if jwk.kty != "EC" || jwk.crv != "P-256" {
        return Err(CoreError::new(
            CoreErrorCode::UnsupportedAlgorithm,
            "VC JOSE/COSE fixture is outside the ES256/P-256 product profile",
        ));
    }
    Ok(())
}

fn ensure_verification_method(method: &VerificationMethod) -> CoreResult<()> {
    let controller_prefix = format!("{}#", method.controller);
    if method.type_ != "JsonWebKey"
        || url::Url::parse(&method.id).is_err()
        || url::Url::parse(&method.controller).is_err()
        || !method.id.starts_with(&controller_prefix)
    {
        return Err(CoreError::new(
            CoreErrorCode::InvalidKey,
            "VC JOSE/COSE fixture must contain a controlled JsonWebKey verification method",
        ));
    }
    Ok(())
}

fn ensure_private_p256(private: &SuitePrivateJwk, public: &SuitePublicJwk) -> CoreResult<()> {
    if private.kty != public.kty
        || private.crv != public.crv
        || private.x != public.x
        || private.y != public.y
    {
        return Err(CoreError::new(
            CoreErrorCode::InvalidKey,
            "VC JOSE/COSE public and private JWK members do not match",
        ));
    }
    Ok(())
}

fn ensure_key_pair(signing_key: &SigningKey, public: &SuitePublicJwk) -> CoreResult<()> {
    let point = signing_key.verifying_key().to_sec1_point(false);
    if b64_encode(point.x().expect("P-256 point has x")) != public.x
        || b64_encode(point.y().expect("P-256 point has y")) != public.y
    {
        return Err(CoreError::new(
            CoreErrorCode::InvalidKey,
            "VC JOSE/COSE private key does not produce the declared public key",
        ));
    }
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &str) -> CoreResult<T> {
    let bytes = fs::read(path).map_err(|_| {
        CoreError::new(
            CoreErrorCode::InvalidInput,
            "VC JOSE/COSE JSON fixture could not be read",
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|_| {
        CoreError::new(
            CoreErrorCode::InvalidInput,
            "VC JOSE/COSE JSON fixture is malformed",
        )
    })
}

fn required_argument(name: &str) -> CoreResult<String> {
    argument(name).ok_or_else(|| {
        CoreError::new(
            CoreErrorCode::InvalidInput,
            format!("missing conformance argument: {name}"),
        )
    })
}

fn argument(name: &str) -> Option<String> {
    let mut arguments = env::args();
    while let Some(argument) = arguments.next() {
        if argument == name {
            return arguments.next();
        }
    }
    None
}
