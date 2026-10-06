//! Single conformant VC/SD-JWT core for the UNSW credential POC.
//!
//! This crate is pure logic: no HTTP server, no database, and no ambient I/O.
//! External effects are injected through documented ports so unit tests can use
//! fixed clocks, fake resolvers, and deterministic salt sources.

mod partner_identity_proof;
pub use partner_identity_proof::{PartnerIdentityProofOptions, verify_partner_identity_proof};

mod issuer_authorizations;
pub use issuer_authorizations::{
    ISSUER_AUTHORIZATIONS_MAX_TTL_SECONDS, ISSUER_AUTHORIZATIONS_TYP, IssuerAuthorization,
    IssuerAuthorizationRequest, IssuerAuthorizations, sign_issuer_authorizations,
    verify_issuer_authorization, verify_scalar_credential_authorization,
};

mod scalar_definitions;
pub use scalar_definitions::{
    ScalarClaim, ScalarCredentialDefinition, ScalarDisclosureProfile, ScalarValueType,
    SubjectValidationMode, validate_scalar_definition, validate_scalar_subject,
};

mod scoped_permissions;
pub use scoped_permissions::{
    SCOPED_VERIFIER_PERMISSIONS_MAX_TTL_SECONDS, SCOPED_VERIFIER_PERMISSIONS_TYP,
    SCOPED_VERIFIER_PERMISSIONS_VERSION, ScopedVerifierPermission, ScopedVerifierPermissionRequest,
    ScopedVerifierPermissionResult, ScopedVerifierPermissions, sign_scoped_verifier_permissions,
    verify_scoped_verifier_permission,
};

mod local_signer;
mod w3c_vc_data_model;
pub use local_signer::LocalSigner;

pub use w3c_vc_data_model::{
    validate_w3c_vc_data_model_credential, validate_w3c_vc_data_model_presentation,
};

use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    error::Error,
    fmt,
};

use aes_gcm::{
    Aes128Gcm, Aes256Gcm, Nonce,
    aead::{Aead as _, KeyInit as _, Payload},
};
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use flate2::{
    Compression,
    read::{DeflateDecoder, GzDecoder, ZlibDecoder},
    write::{DeflateEncoder, GzEncoder},
};
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer as _, Verifier as _},
};
use p256::elliptic_curve::sec1::ToSec1Point as _;
use p256::{PublicKey, SecretKey, ecdh::diffie_hellman};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, Error as RcgenError, IsCa,
    Issuer, KeyIdMethod, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PublicKeyData, SerialNumber,
    SignatureAlgorithm, SigningKey as RcgenSigningKey,
};
use rustls_pki_types::{CertificateDer, UnixTime};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use std::io::{Read as _, Write as _};
use url::Url;
use webpki::{EndEntityCert, KeyUsage as WebPkiKeyUsage, anchor_from_trusted_cert};
use x509_parser::{
    extensions::ParsedExtension,
    oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY},
    pem::parse_x509_pem,
    prelude::parse_x509_certificate,
    time::ASN1Time,
};
use zeroize::Zeroizing;

const SD_ALG_SHA_256: &str = "sha-256";
const ISSUER_JWT_MAX_FUTURE_NBF_SKEW_SECONDS: i64 = 60;
const VC_SD_JWT_TYP: &str = "vc+sd-jwt";
const DC_SD_JWT_TYP: &str = "dc+sd-jwt";
const KB_JWT_TYP: &str = "kb+jwt";
const SD_JWT_SALT_BYTES: usize = 16;
const DID_CONTEXT: &str = "https://www.w3.org/ns/did/v1";
const DID_WEB_METHOD_PREFIX: &str = "did:web:";
const DID_VERIFICATION_METHOD_TYPE: &str = "JsonWebKey";
const BITSTRING_STATUS_LIST_CREDENTIAL_TYPE: &str = "BitstringStatusListCredential";
const BITSTRING_STATUS_LIST_TYPE: &str = "BitstringStatusList";
const BITSTRING_STATUS_LIST_ENTRY_TYPE: &str = "BitstringStatusListEntry";
const TRUST_LIST_TYP: &str = "trust-list+jwt";
const OID4VP_REQUEST_TYP: &str = "oauth-authz-req+jwt";
const OID4VP_WALLET_AUDIENCE: &str = "https://self-issued.me/v2";
const OID4VP_DECENTRALIZED_IDENTIFIER_PREFIX: &str = "decentralized_identifier:";
const OID4VCI_JWE_ALG: &str = "ECDH-ES";
const OID4VCI_JWE_ENC: &str = "A256GCM";
const OID4VCI_JWE_ZIP: &str = "DEF";
const OID4VCI_JWE_IV_BYTES: usize = 12;
const OID4VCI_JWE_TAG_BYTES: usize = 16;
const OID4VCI_JWE_MAX_PLAINTEXT_BYTES: u64 = 1_048_576;
const OID4VP_JWE_ALG: &str = "ECDH-ES";
const OID4VP_JWE_ENC: &str = "A256GCM";
const OID4VP_JWE_ENC_A128: &str = "A128GCM";
const OID4VP_JWE_IV_BYTES: usize = 12;
const OID4VP_JWE_TAG_BYTES: usize = 16;
const OID4VP_JWE_MAX_PLAINTEXT_BYTES: u64 = 1_048_576;
const OID4VP_MAX_X509_CERTIFICATES: usize = 8;
const OID4VP_MAX_STATUS_LIST_BYTES: u64 = 1_048_576;
const OID4VP_STATUS_LIST_TYP: &str = "statuslist+jwt";

/// W3C Bitstring Status List v1.0 default/minimum list length.
///
/// The W3C Recommendation uses 131,072 one-bit entries, which is 16 KiB before
/// GZIP compression, as the privacy-preserving baseline for status lists.
pub const DEFAULT_STATUS_LIST_BITS: usize = 131_072;

/// Default allowance for small positive holder/verifier clock differences.
///
/// The past-age window remains independently bounded by
/// [`SdJwtVerificationOptions::max_kb_age_seconds`].
pub const DEFAULT_MAX_KB_FUTURE_SKEW_SECONDS: i64 = 5;
pub const DEFAULT_DPOP_FUTURE_SKEW_SECONDS: i64 = 10;

const fn default_max_kb_future_skew_seconds() -> i64 {
    DEFAULT_MAX_KB_FUTURE_SKEW_SECONDS
}

/// Stable result type for all public core operations.
pub type CoreResult<T> = Result<T, CoreError>;

/// Returns the current crate identity for scaffold smoke tests.
#[must_use]
pub fn crate_name() -> &'static str {
    "identity-core"
}

/// Public certificate material for a deterministic development-only signing identity.
///
/// Private key bytes never leave this Rust core. The returned trust anchor is public
/// configuration material for local HAIP conformance, and the `x5c` chain deliberately
/// excludes that self-signed root.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeterministicTestX509Identity {
    pub public_jwk: PublicJwk,
    pub x5c: Vec<String>,
    pub trust_anchor_pem: String,
}

/// Build deterministic public X.509 material for an opaque test issuer slot.
///
/// This is intentionally limited to the labelled `issuer:<0-253>` development slots.
/// The leaf key matches the key installed by the Node binding for the same slot; a
/// separate in-core root signs the leaf and is never returned as private material.
pub fn deterministic_test_x509_identity(
    key_id: &str,
    slot: &str,
) -> CoreResult<DeterministicTestX509Identity> {
    let index = slot
        .strip_prefix("issuer:")
        .and_then(|value| value.parse::<u8>().ok())
        .filter(|value| *value < 254)
        .ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::InvalidInput,
                "X.509 test slot must be issuer:<0-253>",
            )
        })?;
    if key_id.is_empty() {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "X.509 test key identifier is required",
        ));
    }

    let leaf_signing_key = deterministic_test_issuer_signing_key(index)?;
    let root_signing_key = deterministic_test_issuer_signing_key(254)?;
    let leaf_key_pair = DeterministicRcgenP256Key::new(leaf_signing_key.clone());
    let root_key_pair = DeterministicRcgenP256Key::new(root_signing_key);

    let mut root_params = CertificateParams::default();
    root_params.distinguished_name = x509_common_name("UNSW VC Test HAIP Root");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    root_params.key_identifier_method =
        KeyIdMethod::PreSpecified(Sha256::digest(root_key_pair.der_bytes()).to_vec());
    root_params.serial_number = Some(SerialNumber::from(1_u64));
    let root_certificate = root_params.self_signed(&root_key_pair).map_err(|_| {
        CoreError::new(
            CoreErrorCode::SigningFailed,
            "failed to create the X.509 test trust anchor inside Rust",
        )
    })?;
    let root_issuer = Issuer::new(root_params, root_key_pair);

    let mut leaf_params = CertificateParams::default();
    leaf_params.distinguished_name = x509_common_name("UNSW VC HAIP Credential Signer");
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.key_identifier_method =
        KeyIdMethod::PreSpecified(Sha256::digest(leaf_key_pair.der_bytes()).to_vec());
    leaf_params.serial_number = Some(SerialNumber::from(u64::from(index) + 2));
    leaf_params.use_authority_key_identifier_extension = true;
    let leaf_certificate = leaf_params
        .signed_by(&leaf_key_pair, &root_issuer)
        .map_err(|_| {
            CoreError::new(
                CoreErrorCode::SigningFailed,
                "failed to create the X.509 test leaf certificate inside Rust",
            )
        })?;

    Ok(DeterministicTestX509Identity {
        public_jwk: public_jwk_from_verifying_key(
            leaf_signing_key.verifying_key(),
            Some(key_id.to_owned()),
        ),
        x5c: vec![Base64::encode_string(leaf_certificate.der())],
        trust_anchor_pem: root_certificate.pem(),
    })
}

/// Validate a bounded P-256 certificate path against an independently supplied
/// trust anchor and bind its leaf key to the expected JWK.
///
/// The `x5c` path is ordered leaf-first and must exclude the self-signed root.
/// The returned values are the Authority Key Identifiers from every certificate
/// in the supplied path, in the base64url representation used by OID4VP DCQL
/// trusted-authority queries.
pub fn validate_pinned_x509_identity(
    x5c: &[String],
    trust_anchor_pem: &str,
    expected_public_jwk: &PublicJwk,
    now_unix_seconds: i64,
) -> CoreResult<Vec<String>> {
    if x5c.is_empty()
        || x5c.len() > 8
        || x5c
            .iter()
            .any(|value| value.is_empty() || value.len() > 32_768)
        || trust_anchor_pem.is_empty()
        || trust_anchor_pem.len() > 65_536
    {
        return Err(CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "X.509 identity path is missing or outside its bounded size",
        ));
    }
    let now = ASN1Time::from_timestamp(now_unix_seconds).map_err(|_| {
        CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "X.509 validation time is outside the supported range",
        )
    })?;
    let chain_der = x5c
        .iter()
        .map(|value| {
            Base64::decode_vec(value).map_err(|_| {
                CoreError::new(
                    CoreErrorCode::TrustCheckFailed,
                    "X.509 identity path contains invalid base64 DER",
                )
            })
        })
        .collect::<CoreResult<Vec<_>>>()?;
    let (pem_remainder, root_pem) = parse_x509_pem(trust_anchor_pem.as_bytes()).map_err(|_| {
        CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "X.509 trust anchor is not a valid PEM certificate",
        )
    })?;
    if root_pem.label != "CERTIFICATE"
        || pem_remainder
            .iter()
            .any(|value| !value.is_ascii_whitespace())
        || chain_der.iter().any(|value| value == &root_pem.contents)
    {
        return Err(CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "X.509 path must contain one PEM root only and exclude that root from x5c",
        ));
    }
    let (root_remainder, root) = parse_x509_certificate(&root_pem.contents).map_err(|_| {
        CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "X.509 trust anchor certificate is malformed",
        )
    })?;
    let certificates = chain_der
        .iter()
        .map(|value| {
            let (remainder, certificate) = parse_x509_certificate(value).map_err(|_| {
                CoreError::new(
                    CoreErrorCode::TrustCheckFailed,
                    "X.509 identity certificate is malformed",
                )
            })?;
            if !remainder.is_empty() {
                return Err(CoreError::new(
                    CoreErrorCode::TrustCheckFailed,
                    "X.509 identity certificate has trailing data",
                ));
            }
            Ok(certificate)
        })
        .collect::<CoreResult<Vec<_>>>()?;
    let non_self_issued_intermediates = certificates
        .iter()
        .skip(1)
        .filter(|certificate| certificate.subject() != certificate.issuer())
        .count();
    if !root_remainder.is_empty()
        || root.subject() != root.issuer()
        || !root.validity().is_valid_at(now)
        || !certificate_is_ca(&root)
        || !certificate_allows_cert_signing(&root)
        || !certificate_path_len_allows(&root, non_self_issued_intermediates)
        || root.verify_signature(None).is_err()
    {
        return Err(CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "X.509 trust anchor is not a valid self-signed CA",
        ));
    }

    let webpki_root = CertificateDer::from(root_pem.contents.as_slice());
    let trust_anchor = anchor_from_trusted_cert(&webpki_root).map_err(|_| {
        CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "X.509 trust anchor cannot be used for standards-complete path validation",
        )
    })?;
    let webpki_chain = chain_der
        .iter()
        .map(|certificate| CertificateDer::from(certificate.as_slice()))
        .collect::<Vec<_>>();
    let webpki_leaf = EndEntityCert::try_from(&webpki_chain[0]).map_err(|_| {
        CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "X.509 identity leaf is malformed",
        )
    })?;
    webpki_leaf
        .verify_for_usage(
            &[webpki::ring::ECDSA_P256_SHA256],
            std::slice::from_ref(&trust_anchor),
            &webpki_chain[1..],
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(
                u64::try_from(now_unix_seconds).map_err(|_| {
                    CoreError::new(
                        CoreErrorCode::TrustCheckFailed,
                        "X.509 validation time is outside the supported range",
                    )
                })?,
            )),
            WebPkiKeyUsage::client_auth(),
            None,
            None,
        )
        .map_err(|_| {
            CoreError::new(
                CoreErrorCode::TrustCheckFailed,
                "X.509 identity certificate path violates its constraints or is untrusted",
            )
        })?;

    for (index, certificate) in certificates.iter().enumerate() {
        let issuer = certificates.get(index + 1).unwrap_or(&root);
        if !certificate.validity().is_valid_at(now)
            || certificate.issuer() != issuer.subject()
            || certificate
                .verify_signature(Some(issuer.public_key()))
                .is_err()
            || (index > 0
                && (!certificate_is_ca(certificate)
                    || !certificate_allows_cert_signing(certificate)))
        {
            return Err(CoreError::new(
                CoreErrorCode::TrustCheckFailed,
                "X.509 identity certificate path is invalid or untrusted",
            ));
        }
    }
    let leaf = &certificates[0];
    if certificate_is_ca(leaf) || !certificate_allows_digital_signature(leaf) {
        return Err(CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "X.509 identity leaf is not a signing end-entity certificate",
        ));
    }
    let expected_point = verifying_key_from_jwk(expected_public_jwk)?
        .to_sec1_point(false)
        .as_bytes()
        .to_vec();
    if leaf.public_key().subject_public_key.data.as_ref() != expected_point {
        return Err(CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "X.509 identity leaf public key does not match the expected JWK",
        ));
    }
    let leaf_authority_key_identifier = leaf
        .extensions()
        .iter()
        .find_map(|extension| match extension.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(identifier) => identifier
                .key_identifier
                .as_ref()
                .map(|value| Base64UrlUnpadded::encode_string(value.0)),
            _ => None,
        })
        .ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::TrustCheckFailed,
                "X.509 identity leaf is missing an Authority Key Identifier",
            )
        })?;
    let mut authority_key_identifiers = certificates
        .iter()
        .flat_map(|certificate| certificate.extensions())
        .filter_map(|extension| match extension.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(identifier) => identifier
                .key_identifier
                .as_ref()
                .map(|value| Base64UrlUnpadded::encode_string(value.0)),
            _ => None,
        })
        .collect::<Vec<_>>();
    if authority_key_identifiers.first() != Some(&leaf_authority_key_identifier) {
        return Err(CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "X.509 identity leaf Authority Key Identifier is unavailable",
        ));
    }
    authority_key_identifiers.dedup();
    Ok(authority_key_identifiers)
}

fn certificate_is_ca(certificate: &x509_parser::certificate::X509Certificate<'_>) -> bool {
    certificate
        .basic_constraints()
        .ok()
        .flatten()
        .is_some_and(|constraints| constraints.value.ca)
}

fn certificate_allows_cert_signing(
    certificate: &x509_parser::certificate::X509Certificate<'_>,
) -> bool {
    certificate
        .key_usage()
        .ok()
        .flatten()
        .is_some_and(|usage| usage.value.key_cert_sign())
}

fn certificate_allows_digital_signature(
    certificate: &x509_parser::certificate::X509Certificate<'_>,
) -> bool {
    certificate
        .key_usage()
        .ok()
        .flatten()
        .is_some_and(|usage| usage.value.digital_signature())
}

fn certificate_path_len_allows(
    certificate: &x509_parser::certificate::X509Certificate<'_>,
    subordinate_ca_certificates: usize,
) -> bool {
    certificate
        .basic_constraints()
        .ok()
        .flatten()
        .is_some_and(|constraints| {
            constraints.value.ca
                && constraints.value.path_len_constraint.is_none_or(|maximum| {
                    subordinate_ca_certificates <= usize::try_from(maximum).unwrap_or(usize::MAX)
                })
        })
}

fn deterministic_test_issuer_signing_key(index: u8) -> CoreResult<SigningKey> {
    let mut scalar = [0_u8; 32];
    scalar[31] = index.checked_add(1).ok_or_else(|| {
        CoreError::new(
            CoreErrorCode::InvalidInput,
            "X.509 test issuer slot is invalid",
        )
    })?;
    SigningKey::from_slice(&scalar).map_err(|_| {
        CoreError::new(
            CoreErrorCode::InvalidKey,
            "X.509 deterministic test scalar is invalid",
        )
    })
}

struct DeterministicRcgenP256Key {
    signing_key: SigningKey,
    public_key: Vec<u8>,
}

impl DeterministicRcgenP256Key {
    fn new(signing_key: SigningKey) -> Self {
        let public_key = signing_key
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        Self {
            signing_key,
            public_key,
        }
    }
}

impl PublicKeyData for DeterministicRcgenP256Key {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

impl RcgenSigningKey for DeterministicRcgenP256Key {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RcgenError> {
        let signature: Signature = self.signing_key.sign(message);
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

fn x509_common_name(common_name: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, common_name);
    name
}

/// Stable cross-binding error-code enum.
///
/// Bindings mirror this enum verbatim so every surface names the same failing
/// check when verification rejects a credential or presentation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoreErrorCode {
    InvalidInput,
    UnsupportedAlgorithm,
    InvalidKey,
    InvalidSignature,
    MalformedJws,
    JsonSerialization,
    KeyNotFound,
    SigningFailed,
    VerificationFailed,
    ClockUnavailable,
    ResolverUnavailable,
    SaltUnavailable,
    TrustCheckFailed,
    StatusCheckFailed,
    StatusListStale,
    BindingCheckFailed,
    FreshnessCheckFailed,
    AttachmentCheckFailed,
    DisclosureDigestMismatch,
    MissingDisclosure,
}

/// Error value carrying a stable code plus human-readable context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreError {
    code: CoreErrorCode,
    message: String,
}

impl CoreError {
    #[must_use]
    pub fn new(code: CoreErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    #[must_use]
    pub fn code(&self) -> CoreErrorCode {
        self.code
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl Error for CoreError {}

/// Opaque key handle passed across FFI boundaries.
///
/// Bindings pass handles like this, never private key bytes. Keystore
/// implementations load and use key material inside Rust.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct KeyId(String);

impl KeyId {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Issuer signing port.
///
/// POC implementation: encrypted local keystore. Production swap: KMS/HSM or
/// quorum-backed signer. Private keys never cross this trait boundary.
pub trait Signer {
    fn sign(&self, key_id: &KeyId, signing_input: &[u8]) -> CoreResult<Vec<u8>>;
}

/// Issuer key lookup port.
///
/// Exposes public key material only. Production implementations may read from a
/// local encrypted keystore, KMS metadata, or a trust-list cache.
pub trait KeyStore {
    fn public_jwk(&self, key_id: &KeyId) -> CoreResult<PublicJwk>;
}

/// Wallet device-key port.
///
/// Real wallet implementation: Secure Enclave / StrongBox. Emulator
/// development may use a loudly-labelled software implementation.
pub trait HolderKeyStore {
    fn generate_holder_key(&mut self) -> CoreResult<KeyId>;
    fn holder_public_jwk(&self, key_id: &KeyId) -> CoreResult<PublicJwk>;
    fn sign_with_holder_key(&self, key_id: &KeyId, signing_input: &[u8]) -> CoreResult<Vec<u8>>;
}

/// Injected time source.
///
/// Unit tests use fixed clocks; production supplies current Unix time.
pub trait Clock {
    fn now_unix_seconds(&self) -> CoreResult<i64>;
}

/// Injected DID/metadata resolver.
///
/// Unit tests use fake in-memory responses. Runtime services decide how to
/// perform HTTPS, caching, retries, and trust-root handling outside this crate.
pub trait HttpResolver {
    fn resolve(&self, url: &str) -> CoreResult<Vec<u8>>;
}

/// Injected salt/entropy source for SD-JWT disclosures and decoy digests.
///
/// Production implementation: OS CSPRNG via `getrandom`, with salts at least
/// 128-bit. Fixed implementations exist only for deterministic vectors.
pub trait SaltSource {
    fn salt(&mut self, byte_len: usize) -> CoreResult<Vec<u8>>;
}

/// OS-backed production salt source.
#[derive(Debug, Default)]
pub struct OsSaltSource;

impl SaltSource for OsSaltSource {
    fn salt(&mut self, byte_len: usize) -> CoreResult<Vec<u8>> {
        let mut salt = vec![0_u8; byte_len];
        getrandom::fill(&mut salt).map_err(|error| {
            CoreError::new(
                CoreErrorCode::SaltUnavailable,
                format!("OS CSPRNG unavailable: {error}"),
            )
        })?;
        Ok(salt)
    }
}

/// Deterministic salt source for golden-vector tests.
#[derive(Clone, Debug)]
pub struct FixedSaltSource {
    salts: VecDeque<Vec<u8>>,
}

impl FixedSaltSource {
    #[must_use]
    pub fn new(salts: impl IntoIterator<Item = Vec<u8>>) -> Self {
        Self {
            salts: salts.into_iter().collect(),
        }
    }
}

impl SaltSource for FixedSaltSource {
    fn salt(&mut self, byte_len: usize) -> CoreResult<Vec<u8>> {
        let salt = self
            .salts
            .pop_front()
            .ok_or_else(|| CoreError::new(CoreErrorCode::SaltUnavailable, "no fixed salt left"))?;

        if salt.len() != byte_len {
            return Err(CoreError::new(
                CoreErrorCode::SaltUnavailable,
                format!("fixed salt length {}, expected {byte_len}", salt.len()),
            ));
        }

        Ok(salt)
    }
}

/// Public P-256 JWK. Private components are intentionally not modelled.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

impl PublicJwk {
    #[must_use]
    pub fn p256(x: impl Into<String>, y: impl Into<String>, kid: Option<String>) -> Self {
        Self {
            kty: "EC".to_owned(),
            crv: "P-256".to_owned(),
            x: x.into(),
            y: y.into(),
            kid,
        }
    }
}

/// Public P-256 JWK used for OID4VCI and OID4VP ECDH-ES encryption.
///
/// Private JWK members are intentionally not represented; unknown members are
/// refused before the value crosses a language binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwePublicJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub key_use: Option<String>,
}

impl JwePublicJwk {
    #[must_use]
    pub fn from_public_key(
        public_key: PublicKey,
        kid: Option<String>,
        alg: Option<String>,
    ) -> Self {
        let encoded = public_key.to_sec1_point(false);
        Self {
            kty: "EC".to_owned(),
            crv: "P-256".to_owned(),
            x: b64_encode(encoded.x().expect("uncompressed P-256 point has x")),
            y: b64_encode(encoded.y().expect("uncompressed P-256 point has y")),
            kid,
            alg,
            key_use: Some("enc".to_owned()),
        }
    }
}

/// Wallet-selected encryption parameters carried in an OID4VCI Credential Request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Oid4vciCredentialResponseEncryption {
    pub jwk: JwePublicJwk,
    pub enc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zip: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Oid4vciJweHeader {
    alg: String,
    enc: String,
    cty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    crit: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    epk: Option<JwePublicJwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    apu: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    apv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    zip: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Oid4vpJweHeader {
    alg: String,
    enc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cty: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    crit: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    epk: Option<JwePublicJwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    apu: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    apv: Option<String>,
}

/// DID document subset used for issuer `did:web` identities.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<DidVerificationMethod>,
    #[serde(rename = "assertionMethod")]
    pub assertion_method: Vec<String>,
    pub authentication: Vec<String>,
}

/// Public-key verification method in an issuer DID document.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DidVerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub controller: String,
    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: PublicJwk,
}

/// Planned issuer identity from the constitution's five-issuer taxonomy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlannedIssuerDid {
    pub key: String,
    pub label: String,
    pub host: String,
    pub did: String,
    pub credential_types: Vec<String>,
}

/// Compact JWS header for the subset this core supports.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JwsHeader {
    pub alg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cty: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<PublicJwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
}

impl JwsHeader {
    #[must_use]
    pub fn es256(typ: impl Into<Option<String>>, kid: impl Into<Option<String>>) -> Self {
        Self {
            alg: "ES256".to_owned(),
            typ: typ.into(),
            cty: None,
            kid: kid.into(),
            jwk: None,
            x5c: None,
        }
    }
}

/// Explicit OIDF wallet-presentation profile. This never changes the normal
/// ecosystem `vc+sd-jwt` path.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Oid4vpWalletInteropProfile {
    Final,
    Haip,
}

/// Trusted outer-activation facts supplied to the pure request validator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Oid4vpWalletRequestPolicy {
    pub profile: Oid4vpWalletInteropProfile,
    pub activation_client_id: String,
    pub expected_client_id: String,
    pub request_uri: String,
    pub expected_origin: String,
    /// Complete leaf-first verifier certificate chain validated by the caller.
    pub expected_x5c: Option<Vec<String>>,
    /// Claims available from the already verified held credential. Values are
    /// used only for local DCQL selection and are never included in evidence.
    pub available_claims: BTreeMap<String, Value>,
    /// Authority Key Identifiers from the verified held-credential chain.
    pub trusted_authority_key_identifiers: Vec<String>,
}

/// One DCQL query selected for a separately minimized presentation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Oid4vpWalletCredentialSelection {
    pub credential_id: String,
    pub requested_claims: Vec<String>,
}

/// Request fields released only after signature, identity, metadata and DCQL
/// validation succeeds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VerifiedOid4vpWalletInteropRequest {
    pub payload: Value,
    pub credential_selections: Vec<Oid4vpWalletCredentialSelection>,
    pub dcql_satisfied: bool,
    pub encryption_key: Option<JwePublicJwk>,
}

/// Verified compact JWS parts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifiedJws {
    pub header: JwsHeader,
    pub payload: Vec<u8>,
}

/// Request-specific checks for an RFC 9449 DPoP proof.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DpopVerificationOptions {
    pub expected_htu: String,
    pub expected_htm: String,
    pub now_unix_seconds: i64,
    pub max_age_seconds: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_nonce: Option<String>,
}

/// Verified, non-secret DPoP binding material returned to protocol adapters.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifiedDpopProof {
    pub public_jwk: PublicJwk,
    pub public_jwk_sha256_thumbprint: String,
    pub htu: String,
    pub htm: String,
    pub iat: i64,
    pub jti: String,
}

/// Request-specific checks for an OAuth client-attestation JWT and its proof of possession.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClientAttestationVerificationOptions {
    pub trusted_attester_jwk: PublicJwk,
    pub expected_attester_issuer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_client_id: Option<String>,
    pub expected_audience: String,
    pub now_unix_seconds: i64,
    pub max_age_seconds: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_challenge: Option<String>,
}

/// Verified, non-secret client-instance binding material returned to protocol adapters.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifiedClientAttestation {
    pub client_id: String,
    pub client_instance_jwk: PublicJwk,
    pub client_instance_jwk_sha256_thumbprint: String,
    pub attestation_issued_at: i64,
    pub proof_issued_at: i64,
    pub proof_jti: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
struct DpopClaims {
    htu: String,
    htm: String,
    iat: i64,
    jti: String,
    #[serde(default)]
    ath: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
struct ClientAttestationConfirmation {
    jwk: PublicJwk,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
struct ClientAttestationClaims {
    iss: String,
    #[serde(default)]
    sub: Option<String>,
    iat: i64,
    #[serde(default)]
    nbf: Option<i64>,
    exp: i64,
    cnf: ClientAttestationConfirmation,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
struct ClientAttestationProofClaims {
    iss: String,
    aud: String,
    iat: i64,
    #[serde(default)]
    nbf: Option<i64>,
    exp: i64,
    jti: String,
    #[serde(default)]
    challenge: Option<String>,
}

/// Verified OID4VP 1.0 Authorization Request Object.
///
/// The verifier DID is derived from the prefixed `client_id`; an `iss` claim,
/// when present, is intentionally ignored as required by OID4VP.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifiedOid4vpRequest {
    pub header: JwsHeader,
    pub payload: Value,
    pub verifier_did: String,
}

/// A top-level or nested object claim that should become selectively disclosable.
///
/// `object_path` points to the object containing `claim_name`. For example,
/// `["credentialSubject"] + "enrolled"` redacts
/// `payload.credentialSubject.enrolled`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DisclosureSpec {
    pub object_path: Vec<String>,
    pub claim_name: String,
}

impl DisclosureSpec {
    #[must_use]
    pub fn new(
        object_path: impl IntoIterator<Item = impl Into<String>>,
        claim_name: impl Into<String>,
    ) -> Self {
        Self {
            object_path: object_path.into_iter().map(Into::into).collect(),
            claim_name: claim_name.into(),
        }
    }

    #[must_use]
    pub fn full_path(&self) -> Vec<String> {
        let mut path = self.object_path.clone();
        path.push(self.claim_name.clone());
        path
    }
}

/// Metadata for a disclosure produced during issuance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IssuedDisclosure {
    pub object_path: Vec<String>,
    pub claim_name: String,
    pub salt: String,
    pub encoded: String,
    pub digest: String,
}

impl IssuedDisclosure {
    #[must_use]
    pub fn full_path(&self) -> Vec<String> {
        let mut path = self.object_path.clone();
        path.push(self.claim_name.clone());
        path
    }
}

/// Issuer-signed SD-JWT plus the disclosure metadata needed by a holder.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IssuedSdJwt {
    pub issuer_jwt: String,
    pub compact: String,
    pub payload: Value,
    pub disclosures: Vec<IssuedDisclosure>,
}

/// A named disclosure profile from `specs/credentials.md`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DisclosureProfile {
    pub name: String,
    pub claim_paths: Vec<Vec<String>>,
    /// Explicitly opt this presentation into format-specific interop semantics.
    /// Absence preserves the normal ecosystem `vc+sd-jwt` presentation behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_format: Option<CredentialFormat>,
}

impl DisclosureProfile {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        claim_paths: impl IntoIterator<Item = impl IntoIterator<Item = impl Into<String>>>,
    ) -> Self {
        Self {
            name: name.into(),
            claim_paths: claim_paths
                .into_iter()
                .map(|path| path.into_iter().map(Into::into).collect())
                .collect(),
            credential_format: None,
        }
    }

    #[must_use]
    pub fn with_credential_format(mut self, credential_format: CredentialFormat) -> Self {
        self.credential_format = Some(credential_format);
        self
    }

    #[must_use]
    pub fn uc3_study_space() -> Self {
        Self::new(
            "uc3_study_space",
            [
                ["credentialSubject", "enrolled"],
                ["credentialSubject", "institution_id"],
            ],
        )
    }

    #[must_use]
    pub fn uc4_exam_hall() -> Self {
        Self::new(
            "uc4_exam_hall",
            [
                ["credentialSubject", "enrolled"],
                ["credentialSubject", "family_name"],
                ["credentialSubject", "given_name"],
                ["credentialSubject", "student_id"],
                ["credentialSubject", "photo_hash"],
            ],
        )
    }

    fn contains_path(&self, path: &[String]) -> bool {
        self.claim_paths.iter().any(|claim_path| claim_path == path)
    }
}

/// Holder-built SD-JWT+KB presentation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SdJwtPresentation {
    pub presentation: String,
    pub disclosed_sd_jwt: String,
    pub selected_disclosures: Vec<String>,
    pub kb_jwt: String,
    pub sd_hash: String,
}

/// Signature encoding returned by an opaque platform P-256 signer.
///
/// Android Keystore and Apple Security APIs return ASN.1 DER ECDSA signatures;
/// deterministic host signers commonly return the JOSE/P1363 `r || s` form.
/// Normalization into compact-JWS bytes remains exclusively in this core.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalSignatureFormat {
    P1363,
    Asn1Der,
}

/// The only bytes an opaque platform key is asked to sign.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PreparedExternalJws {
    pub operation: ExternalJwsOperation,
    pub algorithm: String,
    pub key_id: KeyId,
    pub public_jwk: PublicJwk,
    pub signing_input: String,
}

/// Core-owned purpose attached to an external signing request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalJwsOperation {
    Oid4vciKeyProof,
    KbJwt,
}

/// Presentation state held while an opaque platform key signs its KB-JWT.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PreparedSdJwtPresentation {
    pub disclosed_sd_jwt: String,
    pub selected_disclosures: Vec<String>,
    pub sd_hash: String,
    pub jws: PreparedExternalJws,
}

/// Verification policy for one verifier request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SdJwtVerificationOptions {
    pub audience: String,
    pub nonce: String,
    pub now_unix_seconds: i64,
    pub max_kb_age_seconds: i64,
    #[serde(default = "default_max_kb_future_skew_seconds")]
    pub max_kb_future_skew_seconds: i64,
    pub required_claims: Vec<Vec<String>>,
    pub expected_typ: Option<String>,
}

/// Fail-closed policy for the dedicated OIDF verifier test profile.
///
/// The suite's synthetic issuer is pinned independently from the ecosystem
/// trust list. HAIP callers populate the AKI values only from Rust-validated
/// issuer certificate paths.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Oid4vpConformanceVerificationPolicy {
    pub audience: String,
    pub nonce: String,
    pub now_unix_seconds: i64,
    pub max_kb_age_seconds: i64,
    #[serde(default = "default_max_kb_future_skew_seconds")]
    pub max_kb_future_skew_seconds: i64,
    pub trusted_issuer: String,
    pub expected_vct: String,
    pub required_claims: Vec<Vec<String>>,
    #[serde(default)]
    pub trusted_authority_key_identifiers: Vec<String>,
}

/// Both certificate-bound client identifiers for one OID4VP verifier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Oid4vpX509ClientIds {
    pub x509_san_dns: String,
    pub x509_hash: String,
}

/// Explicit credential envelope profile.
///
/// The ecosystem primary format is W3C VC Data Model secured with SD-JWT
/// (`vc+sd-jwt`). The IETF SD-JWT VC profile (`dc+sd-jwt`) is exposed only for
/// conformance and external-wallet interop slices.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialFormat {
    W3cVcDataModel,
    IetfSdJwtVc,
}

impl CredentialFormat {
    #[must_use]
    pub fn expected_typ(self) -> &'static str {
        match self {
            Self::W3cVcDataModel => VC_SD_JWT_TYP,
            Self::IetfSdJwtVc => DC_SD_JWT_TYP,
        }
    }

    fn validate_payload(self, payload: &Value) -> CoreResult<()> {
        match self {
            Self::W3cVcDataModel => {
                validate_w3c_vc_data_model_credential(payload)?;
                validate_w3c_vc_jwt_claims(payload)
            }
            Self::IetfSdJwtVc => {
                if payload.get("vct").and_then(Value::as_str).is_none() {
                    return Err(CoreError::new(
                        CoreErrorCode::InvalidInput,
                        "IETF SD-JWT VC payload must contain a string vct claim",
                    ));
                }
                Ok(())
            }
        }
    }
}

/// Verification policy for an issuer SD-JWT credential without a KB-JWT.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SdJwtCredentialVerificationOptions {
    pub now_unix_seconds: i64,
    pub required_claims: Vec<Vec<String>>,
    pub format: CredentialFormat,
}

/// Format-specific options for issuing an SD-JWT credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SdJwtIssueOptions {
    pub decoy_digests: usize,
    pub format: CredentialFormat,
}

/// Verified issuer SD-JWT with selected disclosures materialized into payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VerifiedSdJwtCredential {
    pub issuer_header: JwsHeader,
    pub processed_payload: Value,
    #[serde(skip)]
    disclosed_claim_paths: Vec<Vec<String>>,
}

impl SdJwtVerificationOptions {
    #[must_use]
    pub fn for_profile(
        audience: impl Into<String>,
        nonce: impl Into<String>,
        now_unix_seconds: i64,
        profile: &DisclosureProfile,
    ) -> Self {
        Self {
            audience: audience.into(),
            nonce: nonce.into(),
            now_unix_seconds,
            max_kb_age_seconds: 300,
            max_kb_future_skew_seconds: DEFAULT_MAX_KB_FUTURE_SKEW_SECONDS,
            required_claims: profile.claim_paths.clone(),
            expected_typ: Some(VC_SD_JWT_TYP.to_owned()),
        }
    }
}

/// Verified SD-JWT+KB with selected disclosures materialized into the payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VerifiedSdJwtPresentation {
    pub issuer_header: JwsHeader,
    pub kb_header: JwsHeader,
    pub processed_payload: Value,
    #[serde(skip)]
    disclosed_claim_paths: Vec<Vec<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct KbJwtClaims {
    aud: String,
    nonce: String,
    sd_hash: String,
    iat: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Oid4vciKeyProofClaims {
    aud: String,
    nonce: String,
    iat: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct Oid4vciDpopClaims {
    jti: String,
    htm: String,
    htu: String,
    iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ath: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct Oid4vciConfirmationClaims {
    jwk: PublicJwk,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct Oid4vciClientAttestationClaims {
    iss: String,
    sub: String,
    iat: i64,
    nbf: i64,
    exp: i64,
    cnf: Oid4vciConfirmationClaims,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct Oid4vciClientAttestationPopClaims {
    iss: String,
    aud: String,
    iat: i64,
    nbf: i64,
    exp: i64,
    jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    challenge: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SdJwtPresentationDraft {
    disclosed_sd_jwt: String,
    selected_disclosures: Vec<String>,
    sd_hash: String,
    kb_claims: KbJwtClaims,
}

#[derive(Clone, Debug, PartialEq)]
struct DecodedDisclosure {
    claim_name: String,
    claim_value: Value,
    array_element: bool,
    encoded: String,
    digest: String,
}

/// Sign raw payload bytes as compact JWS using ES256.
pub fn sign_compact_jws(
    header: &JwsHeader,
    payload: &[u8],
    signer: &impl Signer,
    key_id: &KeyId,
) -> CoreResult<String> {
    if header.alg != "ES256" {
        return Err(CoreError::new(
            CoreErrorCode::UnsupportedAlgorithm,
            "only ES256 compact JWS is supported",
        ));
    }

    let protected = encode_json_segment(header)?;
    let payload_segment = b64_encode(payload);
    let signing_input = format!("{protected}.{payload_segment}");
    let signature = signer.sign(key_id, signing_input.as_bytes())?;

    Ok(format!("{}.{}", signing_input, b64_encode(&signature)))
}

/// Sign a serializable payload as compact JWS using serde's JSON encoding.
pub fn sign_compact_jws_json<T: Serialize>(
    header: &JwsHeader,
    payload: &T,
    signer: &impl Signer,
    key_id: &KeyId,
) -> CoreResult<String> {
    let payload = serde_json::to_vec(payload).map_err(json_error)?;
    sign_compact_jws(header, &payload, signer, key_id)
}

/// Create the typed `openid4vci-proof+jwt` profile for a software-backed
/// opaque holder key. Protected-header and claim semantics remain in Rust.
pub fn create_oid4vci_holder_proof(
    audience: &str,
    nonce: &str,
    iat: i64,
    public_jwk: &PublicJwk,
    signer: &impl Signer,
    key_id: &KeyId,
) -> CoreResult<String> {
    ensure_oid4vci_https_identifier(audience, "OID4VCI proof audience")?;
    ensure_oid4vci_required_value(nonce, "OID4VCI proof nonce")?;
    ensure_oid4vci_iat(iat)?;
    let claims = Oid4vciKeyProofClaims {
        aud: audience.to_owned(),
        nonce: nonce.to_owned(),
        iat,
    };
    let mut header = JwsHeader::es256(Some("openid4vci-proof+jwt".to_owned()), None);
    header.jwk = Some(public_jwk.clone());
    sign_and_verify_profile(&header, &claims, public_jwk, signer, key_id)
}

/// Create the typed DPoP proof used by the OID4VCI adapter.
#[allow(clippy::too_many_arguments)]
pub fn create_oid4vci_dpop_proof(
    method: &str,
    target_uri: &str,
    iat: i64,
    jti: &str,
    nonce: Option<&str>,
    access_token: Option<&str>,
    public_jwk: &PublicJwk,
    signer: &impl Signer,
    key_id: &KeyId,
) -> CoreResult<String> {
    if method.is_empty()
        || method.len() > 16
        || !method.bytes().all(|byte| byte.is_ascii_uppercase())
    {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "DPoP HTTP method must contain uppercase ASCII letters",
        ));
    }
    ensure_oid4vci_https_identifier(target_uri, "DPoP target URI")?;
    if target_uri.contains('?') || target_uri.contains('#') {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "DPoP target URI must exclude query and fragment",
        ));
    }
    ensure_oid4vci_required_value(jti, "DPoP proof identifier")?;
    if let Some(value) = nonce {
        ensure_oid4vci_required_value(value, "DPoP nonce")?;
    }
    if let Some(value) = access_token {
        ensure_oid4vci_required_value(value, "DPoP access token")?;
    }
    ensure_oid4vci_iat(iat)?;
    let claims = Oid4vciDpopClaims {
        jti: jti.to_owned(),
        htm: method.to_owned(),
        htu: target_uri.to_owned(),
        iat,
        nonce: nonce.map(str::to_owned),
        ath: access_token.map(|value| sha256_b64url(value.as_bytes())),
    };
    let mut header = JwsHeader::es256(Some("dpop+jwt".to_owned()), None);
    header.jwk = Some(public_jwk.clone());
    sign_and_verify_profile(&header, &claims, public_jwk, signer, key_id)
}

/// Create the typed OAuth client-attestation JWT for the OID4VCI HAIP seam.
#[allow(clippy::too_many_arguments)]
pub fn create_oid4vci_client_attestation(
    attester_issuer: &str,
    client_id: &str,
    iat: i64,
    x5c: &[String],
    instance_public_jwk: &PublicJwk,
    attester_public_jwk: &PublicJwk,
    signer: &impl Signer,
    key_id: &KeyId,
) -> CoreResult<String> {
    ensure_oid4vci_https_identifier(attester_issuer, "client-attester issuer")?;
    ensure_oid4vci_required_value(client_id, "attested client identifier")?;
    ensure_oid4vci_iat(iat)?;
    if x5c.is_empty()
        || x5c.len() > 8
        || x5c
            .iter()
            .any(|certificate| certificate.is_empty() || certificate.len() > 32_768)
    {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "client attestation requires a bounded public certificate chain",
        ));
    }
    let exp = iat.checked_add(300).ok_or_else(|| {
        CoreError::new(
            CoreErrorCode::InvalidInput,
            "client-attestation validity interval overflows",
        )
    })?;
    let claims = Oid4vciClientAttestationClaims {
        iss: attester_issuer.to_owned(),
        sub: client_id.to_owned(),
        iat,
        nbf: iat,
        exp,
        cnf: Oid4vciConfirmationClaims {
            jwk: instance_public_jwk.clone(),
        },
    };
    let mut header = JwsHeader::es256(Some("oauth-client-attestation+jwt".to_owned()), None);
    header.x5c = Some(x5c.to_vec());
    sign_and_verify_profile(&header, &claims, attester_public_jwk, signer, key_id)
}

/// Create the typed proof-of-possession JWT for OAuth client attestation.
#[allow(clippy::too_many_arguments)]
pub fn create_oid4vci_client_attestation_pop(
    client_id: &str,
    audience: &str,
    iat: i64,
    jti: &str,
    challenge: Option<&str>,
    instance_public_jwk: &PublicJwk,
    signer: &impl Signer,
    key_id: &KeyId,
) -> CoreResult<String> {
    ensure_oid4vci_required_value(client_id, "client-attestation proof issuer")?;
    ensure_oid4vci_https_identifier(audience, "client-attestation proof audience")?;
    ensure_oid4vci_required_value(jti, "client-attestation proof identifier")?;
    if let Some(value) = challenge {
        ensure_oid4vci_required_value(value, "client-attestation challenge")?;
    }
    ensure_oid4vci_iat(iat)?;
    let exp = iat.checked_add(300).ok_or_else(|| {
        CoreError::new(
            CoreErrorCode::InvalidInput,
            "client-attestation proof validity interval overflows",
        )
    })?;
    let claims = Oid4vciClientAttestationPopClaims {
        iss: client_id.to_owned(),
        aud: audience.to_owned(),
        iat,
        nbf: iat,
        exp,
        jti: jti.to_owned(),
        challenge: challenge.map(str::to_owned),
    };
    let header = JwsHeader::es256(Some("oauth-client-attestation-pop+jwt".to_owned()), None);
    sign_and_verify_profile(&header, &claims, instance_public_jwk, signer, key_id)
}

fn sign_and_verify_profile<T: Serialize>(
    header: &JwsHeader,
    claims: &T,
    public_jwk: &PublicJwk,
    signer: &impl Signer,
    key_id: &KeyId,
) -> CoreResult<String> {
    verifying_key_from_jwk(public_jwk)?;
    let compact = sign_compact_jws_json(header, claims, signer, key_id)?;
    verify_compact_jws(&compact, public_jwk)?;
    Ok(compact)
}

fn ensure_oid4vci_required_value(value: &str, label: &str) -> CoreResult<()> {
    if value.is_empty()
        || value.len() > 65_536
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            format!("{label} is invalid"),
        ));
    }
    Ok(())
}

fn ensure_oid4vci_https_identifier(value: &str, label: &str) -> CoreResult<()> {
    ensure_oid4vci_required_value(value, label)?;
    let identifier = Url::parse(value).map_err(|_| {
        CoreError::new(
            CoreErrorCode::InvalidInput,
            format!("{label} must be an absolute HTTPS URI"),
        )
    })?;
    if identifier.scheme() != "https"
        || identifier.host_str().is_none()
        || !identifier.username().is_empty()
        || identifier.password().is_some()
        || identifier.fragment().is_some()
    {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            format!("{label} has an invalid HTTPS authority"),
        ));
    }
    Ok(())
}

fn ensure_oid4vci_iat(iat: i64) -> CoreResult<()> {
    if iat <= 0 {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "OID4VCI proof issuance time must be positive",
        ));
    }
    Ok(())
}

fn prepare_external_jws_json<T: Serialize>(
    operation: ExternalJwsOperation,
    header: &JwsHeader,
    payload: &T,
    key_id: &KeyId,
    public_jwk: &PublicJwk,
) -> CoreResult<PreparedExternalJws> {
    validate_external_jws_header(header, key_id, public_jwk)?;
    let protected = encode_json_segment(header)?;
    let payload = serde_json::to_vec(payload).map_err(json_error)?;
    let payload_segment = b64_encode(&payload);
    Ok(PreparedExternalJws {
        operation,
        algorithm: "ES256".to_owned(),
        key_id: key_id.clone(),
        public_jwk: public_jwk.clone(),
        signing_input: format!("{protected}.{payload_segment}"),
    })
}

fn validate_external_jws_header(
    header: &JwsHeader,
    key_id: &KeyId,
    public_jwk: &PublicJwk,
) -> CoreResult<()> {
    if header.alg != "ES256" {
        return Err(CoreError::new(
            CoreErrorCode::UnsupportedAlgorithm,
            "opaque platform signing supports ES256 only",
        ));
    }
    verifying_key_from_jwk(public_jwk)?;
    if header.kid.as_deref() != Some(key_id.as_str()) {
        return Err(CoreError::new(
            CoreErrorCode::InvalidKey,
            "external JWS kid must match the opaque platform key alias",
        ));
    }
    if public_jwk
        .kid
        .as_deref()
        .is_some_and(|kid| kid != key_id.as_str())
    {
        return Err(CoreError::new(
            CoreErrorCode::InvalidKey,
            "platform public JWK kid does not match its opaque alias",
        ));
    }
    if header
        .jwk
        .as_ref()
        .is_some_and(|header_jwk| header_jwk != public_jwk)
    {
        return Err(CoreError::new(
            CoreErrorCode::InvalidKey,
            "external JWS header JWK does not match the platform key",
        ));
    }
    Ok(())
}

fn external_signature(bytes: &[u8], format: ExternalSignatureFormat) -> CoreResult<Signature> {
    match format {
        ExternalSignatureFormat::P1363 => Signature::from_slice(bytes),
        ExternalSignatureFormat::Asn1Der => Signature::from_der(bytes),
    }
    .map_err(|_| {
        CoreError::new(
            CoreErrorCode::InvalidSignature,
            "platform ES256 signature encoding is invalid",
        )
    })
}

fn finalize_external_jws(
    prepared: &PreparedExternalJws,
    signature: &[u8],
    signature_format: ExternalSignatureFormat,
) -> CoreResult<String> {
    if prepared.algorithm != "ES256" {
        return Err(CoreError::new(
            CoreErrorCode::UnsupportedAlgorithm,
            "prepared platform signing algorithm must be ES256",
        ));
    }
    if prepared.signing_input.split('.').count() != 2 {
        return Err(CoreError::new(
            CoreErrorCode::MalformedJws,
            "prepared external JWS must contain two signing-input segments",
        ));
    }
    let verifying_key = verifying_key_from_jwk(&prepared.public_jwk)?;
    let signature = external_signature(signature, signature_format)?;
    verifying_key
        .verify(prepared.signing_input.as_bytes(), &signature)
        .map_err(|_| {
            CoreError::new(
                CoreErrorCode::InvalidSignature,
                "platform signature does not match the prepared signing input and public key",
            )
        })?;

    let compact = format!(
        "{}.{}",
        prepared.signing_input,
        b64_encode(signature.to_bytes().as_ref())
    );
    let verified = verify_compact_jws(&compact, &prepared.public_jwk)?;
    validate_external_jws_header(&verified.header, &prepared.key_id, &prepared.public_jwk)?;
    validate_external_operation(prepared.operation, &verified.header, &verified.payload)?;
    Ok(compact)
}

fn validate_external_operation(
    operation: ExternalJwsOperation,
    header: &JwsHeader,
    payload: &[u8],
) -> CoreResult<()> {
    match operation {
        ExternalJwsOperation::Oid4vciKeyProof => {
            if header.typ.as_deref() != Some("openid4vci-proof+jwt") {
                return Err(CoreError::new(
                    CoreErrorCode::InvalidInput,
                    "OID4VCI proof typ must be openid4vci-proof+jwt",
                ));
            }
            let claims: Oid4vciKeyProofClaims =
                serde_json::from_slice(payload).map_err(json_error)?;
            if claims.aud.trim().is_empty() || claims.nonce.trim().is_empty() {
                return Err(CoreError::new(
                    CoreErrorCode::InvalidInput,
                    "OID4VCI proof audience and nonce are required",
                ));
            }
        }
        ExternalJwsOperation::KbJwt => {
            if header.typ.as_deref() != Some(KB_JWT_TYP) {
                return Err(CoreError::new(
                    CoreErrorCode::InvalidInput,
                    "holder-binding JWS typ must be kb+jwt",
                ));
            }
            let claims: KbJwtClaims = serde_json::from_slice(payload).map_err(json_error)?;
            if claims.aud.trim().is_empty()
                || claims.nonce.trim().is_empty()
                || claims.sd_hash.trim().is_empty()
            {
                return Err(CoreError::new(
                    CoreErrorCode::InvalidInput,
                    "KB-JWT audience, nonce, and sd_hash are required",
                ));
            }
        }
    }
    Ok(())
}

/// Prepare an OID4VCI holder proof for an opaque platform P-256 key.
pub fn prepare_oid4vci_key_proof_external(
    audience: impl Into<String>,
    nonce: impl Into<String>,
    iat: i64,
    key_id: &KeyId,
    public_jwk: &PublicJwk,
) -> CoreResult<PreparedExternalJws> {
    let claims = Oid4vciKeyProofClaims {
        aud: audience.into(),
        nonce: nonce.into(),
        iat,
    };
    let header = JwsHeader::es256(
        Some("openid4vci-proof+jwt".to_owned()),
        Some(key_id.as_str().to_owned()),
    );
    prepare_external_jws_json(
        ExternalJwsOperation::Oid4vciKeyProof,
        &header,
        &claims,
        key_id,
        public_jwk,
    )
}

/// Verify a platform signature and finalize an OID4VCI holder proof.
pub fn finalize_oid4vci_key_proof_external(
    prepared: &PreparedExternalJws,
    signature: &[u8],
    signature_format: ExternalSignatureFormat,
) -> CoreResult<String> {
    if prepared.operation != ExternalJwsOperation::Oid4vciKeyProof {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "prepared external JWS is not an OID4VCI holder proof",
        ));
    }
    finalize_external_jws(prepared, signature, signature_format)
}

/// Issue a W3C VC payload as an SD-JWT.
///
/// The W3C document is validated before the shared disclosure engine removes
/// the exact object claims selected by the caller.
pub fn issue_sd_jwt(
    payload: Value,
    disclosure_specs: &[DisclosureSpec],
    decoy_digests: usize,
    header: &JwsHeader,
    signer: &impl Signer,
    key_id: &KeyId,
    salt_source: &mut impl SaltSource,
) -> CoreResult<IssuedSdJwt> {
    issue_sd_jwt_with_format(
        payload,
        disclosure_specs,
        header,
        signer,
        key_id,
        salt_source,
        SdJwtIssueOptions {
            decoy_digests,
            format: CredentialFormat::W3cVcDataModel,
        },
    )
}

/// Issue an SD-JWT using an explicit credential format profile.
///
/// This is the labelled interop seam for the IETF SD-JWT VC profile. It shares
/// the same disclosure and JOSE machinery as the primary W3C profile and only
/// varies the profile header/payload conventions.
pub fn issue_sd_jwt_with_format(
    payload: Value,
    disclosure_specs: &[DisclosureSpec],
    header: &JwsHeader,
    signer: &impl Signer,
    key_id: &KeyId,
    salt_source: &mut impl SaltSource,
    options: SdJwtIssueOptions,
) -> CoreResult<IssuedSdJwt> {
    let format = options.format;
    let expected_typ = format.expected_typ();
    if header.typ.as_deref() != Some(expected_typ) {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            format!("SD-JWT header typ must be {expected_typ}"),
        ));
    }
    format.validate_payload(&payload)?;
    validate_w3c_vc_jose_header(format, header, &payload)?;
    validate_w3c_vc_disclosure_specs(format, disclosure_specs)?;

    let mut sd_payload = payload;
    let mut disclosures = Vec::with_capacity(disclosure_specs.len());

    for spec in disclosure_specs {
        let claim_value =
            remove_claim_at_path(&mut sd_payload, &spec.object_path, &spec.claim_name)?;
        let salt = b64_encode(&salt_source.salt(SD_JWT_SALT_BYTES)?);
        let encoded = encode_disclosure(&salt, &spec.claim_name, &claim_value)?;
        let digest = sha256_b64url(encoded.as_bytes());
        push_sd_digest_at_path(&mut sd_payload, &spec.object_path, digest.clone())?;
        disclosures.push(IssuedDisclosure {
            object_path: spec.object_path.clone(),
            claim_name: spec.claim_name.clone(),
            salt,
            encoded,
            digest,
        });
    }

    for _ in 0..options.decoy_digests {
        let decoy_digest = sha256_b64url(&salt_source.salt(32)?);
        push_sd_digest_at_path(&mut sd_payload, &[], decoy_digest)?;
    }

    set_object_value_at_path(
        &mut sd_payload,
        &[],
        "_sd_alg".to_owned(),
        Value::String(SD_ALG_SHA_256.to_owned()),
    )?;

    sort_all_sd_digest_arrays(&mut sd_payload)?;

    let issuer_jwt = sign_compact_jws_json(header, &sd_payload, signer, key_id)?;
    let compact = format!(
        "{}{}~",
        issuer_jwt,
        disclosures
            .iter()
            .map(|disclosure| format!("~{}", disclosure.encoded))
            .collect::<String>()
    );

    Ok(IssuedSdJwt {
        issuer_jwt,
        compact,
        payload: sd_payload,
        disclosures,
    })
}

/// Build an SD-JWT+KB presentation for a named disclosure profile.
pub fn present_sd_jwt(
    compact_sd_jwt: &str,
    profile: &DisclosureProfile,
    holder_signer: &impl Signer,
    holder_key_id: &KeyId,
    audience: impl Into<String>,
    nonce: impl Into<String>,
    iat: i64,
) -> CoreResult<SdJwtPresentation> {
    if let Some(format) = profile.credential_format {
        let (issuer_jwt, _, _) = split_sd_jwt(compact_sd_jwt)?;
        let issuer_header: JwsHeader =
            decode_json_segment(issuer_jwt.split('.').next().ok_or_else(|| {
                CoreError::new(CoreErrorCode::MalformedJws, "missing JWS header")
            })?)?;
        if issuer_header.typ.as_deref() != Some(format.expected_typ()) {
            return Err(CoreError::new(
                CoreErrorCode::InvalidInput,
                "presentation credential format does not match the issuer header",
            ));
        }
        format.validate_payload(&decode_jws_payload_unverified(issuer_jwt)?)?;
    }
    let draft = prepare_sd_jwt_presentation_draft(
        compact_sd_jwt,
        profile,
        audience.into(),
        nonce.into(),
        iat,
    )?;
    // The explicitly typed IETF interop seam follows the KB-JWT header profile,
    // which permits only typ and alg. Normal ecosystem profiles retain their
    // opaque key handle as kid and are deliberately unchanged.
    let kb_header = JwsHeader::es256(
        Some(KB_JWT_TYP.to_owned()),
        (profile.credential_format != Some(CredentialFormat::IetfSdJwtVc))
            .then(|| holder_key_id.as_str().to_owned()),
    );
    let kb_jwt = sign_compact_jws_json(&kb_header, &draft.kb_claims, holder_signer, holder_key_id)?;

    Ok(SdJwtPresentation {
        presentation: format!("{}{kb_jwt}", draft.disclosed_sd_jwt),
        disclosed_sd_jwt: draft.disclosed_sd_jwt,
        selected_disclosures: draft.selected_disclosures,
        kb_jwt,
        sd_hash: draft.sd_hash,
    })
}

fn prepare_sd_jwt_presentation_draft(
    compact_sd_jwt: &str,
    profile: &DisclosureProfile,
    audience: String,
    nonce: String,
    iat: i64,
) -> CoreResult<SdJwtPresentationDraft> {
    let (issuer_jwt, disclosures, kb_jwt) = split_sd_jwt(compact_sd_jwt)?;
    if kb_jwt.is_some() {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "expected stored SD-JWT without KB-JWT",
        ));
    }

    let issuer_payload = decode_jws_payload_unverified(issuer_jwt)?;
    let mut selected_disclosures = Vec::new();
    for disclosure in disclosures {
        let decoded = decode_disclosure(disclosure)?;
        let object_path =
            find_sd_digest_path(&issuer_payload, &decoded.digest).ok_or_else(|| {
                CoreError::new(
                    CoreErrorCode::DisclosureDigestMismatch,
                    "disclosure digest is not present in issuer payload",
                )
            })?;
        let mut full_path = object_path;
        full_path.push(decoded.claim_name);
        if profile.contains_path(&full_path) {
            selected_disclosures.push(decoded.encoded);
        }
    }

    let disclosed_sd_jwt = format!(
        "{}{}~",
        issuer_jwt,
        selected_disclosures
            .iter()
            .map(|disclosure| format!("~{disclosure}"))
            .collect::<String>()
    );
    let sd_hash = sha256_b64url(disclosed_sd_jwt.as_bytes());
    let kb_claims = KbJwtClaims {
        aud: audience,
        nonce,
        sd_hash: sd_hash.clone(),
        iat,
    };

    Ok(SdJwtPresentationDraft {
        disclosed_sd_jwt,
        selected_disclosures,
        sd_hash,
        kb_claims,
    })
}

/// Prepare a KB-JWT presentation for an opaque platform P-256 key.
pub fn prepare_sd_jwt_presentation_external(
    compact_sd_jwt: &str,
    profile: &DisclosureProfile,
    holder_key_id: &KeyId,
    holder_public_jwk: &PublicJwk,
    audience: impl Into<String>,
    nonce: impl Into<String>,
    iat: i64,
) -> CoreResult<PreparedSdJwtPresentation> {
    let (issuer_jwt, _, _) = split_sd_jwt(compact_sd_jwt)?;
    let issuer_payload = decode_jws_payload_unverified(issuer_jwt)?;
    let credential_holder_jwk = holder_jwk_from_payload(&issuer_payload)?;
    if public_jwk_sha256_thumbprint(&credential_holder_jwk)?
        != public_jwk_sha256_thumbprint(holder_public_jwk)?
    {
        return Err(CoreError::new(
            CoreErrorCode::BindingCheckFailed,
            "opaque platform key does not match the credential cnf key",
        ));
    }
    let draft = prepare_sd_jwt_presentation_draft(
        compact_sd_jwt,
        profile,
        audience.into(),
        nonce.into(),
        iat,
    )?;
    let kb_header = JwsHeader::es256(
        Some(KB_JWT_TYP.to_owned()),
        Some(holder_key_id.as_str().to_owned()),
    );
    let jws = prepare_external_jws_json(
        ExternalJwsOperation::KbJwt,
        &kb_header,
        &draft.kb_claims,
        holder_key_id,
        holder_public_jwk,
    )?;
    Ok(PreparedSdJwtPresentation {
        disclosed_sd_jwt: draft.disclosed_sd_jwt,
        selected_disclosures: draft.selected_disclosures,
        sd_hash: draft.sd_hash,
        jws,
    })
}

/// Verify a platform signature and finalize an SD-JWT+KB presentation.
pub fn finalize_sd_jwt_presentation_external(
    prepared: &PreparedSdJwtPresentation,
    signature: &[u8],
    signature_format: ExternalSignatureFormat,
) -> CoreResult<SdJwtPresentation> {
    if prepared.jws.operation != ExternalJwsOperation::KbJwt {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "prepared external JWS is not a KB-JWT",
        ));
    }
    if sha256_b64url(prepared.disclosed_sd_jwt.as_bytes()) != prepared.sd_hash {
        return Err(CoreError::new(
            CoreErrorCode::BindingCheckFailed,
            "prepared presentation sd_hash does not match its disclosed SD-JWT",
        ));
    }
    let kb_jwt = finalize_external_jws(&prepared.jws, signature, signature_format)?;
    let (_, claims): (JwsHeader, KbJwtClaims) =
        verify_compact_jws_json(&kb_jwt, &prepared.jws.public_jwk)?;
    if claims.sd_hash != prepared.sd_hash {
        return Err(CoreError::new(
            CoreErrorCode::BindingCheckFailed,
            "platform-signed KB-JWT does not bind the prepared presentation",
        ));
    }
    Ok(SdJwtPresentation {
        presentation: format!("{}{kb_jwt}", prepared.disclosed_sd_jwt),
        disclosed_sd_jwt: prepared.disclosed_sd_jwt.clone(),
        selected_disclosures: prepared.selected_disclosures.clone(),
        kb_jwt,
        sd_hash: prepared.sd_hash.clone(),
    })
}

/// Verify an SD-JWT+KB presentation.
pub fn verify_sd_jwt_presentation(
    presentation: &str,
    issuer_jwk: &PublicJwk,
    options: &SdJwtVerificationOptions,
) -> CoreResult<VerifiedSdJwtPresentation> {
    let (issuer_jwt, disclosures, kb_jwt) = split_sd_jwt(presentation)?;
    let kb_jwt = kb_jwt.ok_or_else(|| {
        CoreError::new(
            CoreErrorCode::BindingCheckFailed,
            "SD-JWT+KB presentation is missing a KB-JWT",
        )
    })?;

    let expected_typ = options.expected_typ.as_deref();
    let verified_issuer = verify_and_materialize_sd_jwt(
        issuer_jwt,
        &disclosures,
        issuer_jwk,
        expected_typ,
        options.now_unix_seconds,
        &options.required_claims,
    )?;
    let payload = verified_issuer.processed_payload;

    let holder_jwk = holder_jwk_from_payload(&payload)?;
    let verified_kb = verify_compact_jws(kb_jwt, &holder_jwk)?;
    if verified_kb.header.typ.as_deref() != Some(KB_JWT_TYP) {
        return Err(CoreError::new(
            CoreErrorCode::BindingCheckFailed,
            "KB-JWT typ must be kb+jwt",
        ));
    }
    let kb_claims: KbJwtClaims =
        serde_json::from_slice(&verified_kb.payload).map_err(json_error)?;
    verify_kb_claims(issuer_jwt, &disclosures, &kb_claims, options)?;

    Ok(VerifiedSdJwtPresentation {
        issuer_header: verified_issuer.issuer_header,
        kb_header: verified_kb.header,
        processed_payload: payload,
        disclosed_claim_paths: verified_issuer.disclosed_claim_paths,
    })
}

/// Verify the pinned synthetic presentation used by the dedicated OIDF
/// verifier profile.
///
/// This composes the ordinary SD-JWT signature, disclosure, holder-binding,
/// audience, nonce, and freshness checks with explicit trust, status, issuer,
/// type, and exact-disclosure policy. The normal ecosystem verifier never
/// calls this labelled `dc+sd-jwt` seam.
pub fn verify_oid4vp_conformance_presentation(
    presentation: &str,
    issuer_jwk: &PublicJwk,
    policy: &Oid4vpConformanceVerificationPolicy,
) -> CoreResult<VerifiedSdJwtPresentation> {
    let verified = verify_oid4vp_presentation_with_key(presentation, issuer_jwk, policy)?;
    if verified.processed_payload.get("status").is_some() {
        return Err(CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "OIDF credential status cannot be accepted without a validated status-list resolver",
        ));
    }
    Ok(verified)
}

/// Verify the Final profile with an injected, read-only Token Status List resolver.
pub fn verify_oid4vp_conformance_presentation_with_status(
    presentation: &str,
    issuer_jwk: &PublicJwk,
    status_resolver: &impl HttpResolver,
    status_trust_anchors_der_base64: &[String],
    policy: &Oid4vpConformanceVerificationPolicy,
) -> CoreResult<VerifiedSdJwtPresentation> {
    let verified = verify_oid4vp_presentation_with_key(presentation, issuer_jwk, policy)?;
    verify_oid4vp_token_status(
        &verified.processed_payload,
        status_resolver,
        status_trust_anchors_der_base64,
        policy.now_unix_seconds,
    )?;
    Ok(verified)
}

/// Verify a HAIP presentation using only its X.509 issuer path and injected
/// read-only status-list resources.
pub fn verify_oid4vp_haip_conformance_presentation(
    presentation: &str,
    issuer_trust_anchors_der_base64: &[String],
    status_resolver: &impl HttpResolver,
    status_trust_anchors_der_base64: &[String],
    policy: &Oid4vpConformanceVerificationPolicy,
) -> CoreResult<VerifiedSdJwtPresentation> {
    let (issuer_jwt, _, _) = split_sd_jwt(presentation)?;
    let header: JwsHeader =
        decode_json_segment(issuer_jwt.split('.').next().ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::MalformedJws,
                "OIDF issuer JWS header is missing",
            )
        })?)?;
    let certificate_chain = header.x5c.as_ref().ok_or_else(|| {
        CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "OIDF HAIP issuer JWS must contain an x5c certificate path",
        )
    })?;
    let validated = validate_oid4vp_x509_signing_chain(
        certificate_chain,
        issuer_trust_anchors_der_base64,
        policy.now_unix_seconds,
    )?;
    if policy.trusted_authority_key_identifiers.is_empty()
        || !validated
            .authority_key_identifiers
            .iter()
            .any(|identifier| {
                policy
                    .trusted_authority_key_identifiers
                    .contains(identifier)
            })
    {
        return Err(CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "OIDF HAIP issuer path does not match the requested AKI authority",
        ));
    }
    let verified =
        verify_oid4vp_presentation_with_key(presentation, &validated.public_jwk, policy)?;
    verify_oid4vp_token_status(
        &verified.processed_payload,
        status_resolver,
        status_trust_anchors_der_base64,
        policy.now_unix_seconds,
    )?;
    Ok(verified)
}

fn verify_oid4vp_presentation_with_key(
    presentation: &str,
    issuer_jwk: &PublicJwk,
    policy: &Oid4vpConformanceVerificationPolicy,
) -> CoreResult<VerifiedSdJwtPresentation> {
    if policy.required_claims.len() != 2
        || policy.required_claims.iter().any(|path| path.len() != 1)
        || policy.required_claims.iter().collect::<HashSet<_>>().len()
            != policy.required_claims.len()
    {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "OIDF Study Space policy must contain exactly two unique claim paths",
        ));
    }
    let options = SdJwtVerificationOptions {
        audience: policy.audience.clone(),
        nonce: policy.nonce.clone(),
        now_unix_seconds: policy.now_unix_seconds,
        max_kb_age_seconds: policy.max_kb_age_seconds,
        max_kb_future_skew_seconds: policy.max_kb_future_skew_seconds,
        required_claims: policy.required_claims.clone(),
        expected_typ: Some(DC_SD_JWT_TYP.to_owned()),
    };
    let verified = verify_sd_jwt_presentation(presentation, issuer_jwk, &options)?;
    let payload = verified.processed_payload.as_object().ok_or_else(|| {
        CoreError::new(
            CoreErrorCode::VerificationFailed,
            "OIDF presentation payload must be a JSON object",
        )
    })?;
    if payload.get("iss").and_then(Value::as_str) != Some(policy.trusted_issuer.as_str()) {
        return Err(CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "OIDF presentation issuer does not match the pinned suite ceremony",
        ));
    }
    if payload.get("vct").and_then(Value::as_str) != Some(policy.expected_vct.as_str()) {
        return Err(CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "OIDF presentation credential type is not trusted for this profile",
        ));
    }

    let disclosed = verified
        .disclosed_claim_paths
        .iter()
        .cloned()
        .collect::<HashSet<_>>();
    let required = policy
        .required_claims
        .iter()
        .cloned()
        .collect::<HashSet<_>>();
    if disclosed != required {
        return Err(CoreError::new(
            CoreErrorCode::MissingDisclosure,
            "OIDF presentation does not disclose exactly the two requested profile claims",
        ));
    }
    if policy
        .required_claims
        .iter()
        .any(|path| payload.get(&path[0]).is_none_or(|value| !value.is_string()))
        || !oid4vp_protocol_containers_have_exact_shape(payload)
    {
        return Err(CoreError::new(
            CoreErrorCode::MissingDisclosure,
            "OIDF presentation claim values do not match the exact profile schema",
        ));
    }
    for (name, value) in payload {
        if oid4vp_protocol_claim(name) {
            continue;
        }
        if !value.is_string() || !required.contains(&vec![name.clone()]) {
            return Err(CoreError::new(
                CoreErrorCode::MissingDisclosure,
                "OIDF presentation contains a clear or unrequested application attribute",
            ));
        }
    }
    Ok(verified)
}

fn oid4vp_protocol_claim(name: &str) -> bool {
    matches!(
        name,
        "iss" | "vct" | "iat" | "nbf" | "exp" | "cnf" | "status" | "_sd" | "_sd_alg"
    )
}

fn oid4vp_protocol_containers_have_exact_shape(payload: &Map<String, Value>) -> bool {
    let Some(cnf) = payload.get("cnf").and_then(Value::as_object) else {
        return false;
    };
    if cnf.len() != 1 || !cnf.contains_key("jwk") {
        return false;
    }
    let Some(jwk) = cnf.get("jwk").and_then(Value::as_object) else {
        return false;
    };
    let required_jwk_members = ["kty", "crv", "x", "y"];
    if required_jwk_members
        .iter()
        .any(|name| jwk.get(*name).is_none_or(|value| !value.is_string()))
        || jwk.iter().any(|(name, value)| {
            name != "kid" && !required_jwk_members.contains(&name.as_str())
                || name == "kid" && !value.is_string()
        })
    {
        return false;
    }

    let Some(status) = payload.get("status") else {
        return true;
    };
    let Some(status) = status.as_object() else {
        return false;
    };
    if status.len() != 1 || !status.contains_key("status_list") {
        return false;
    }
    let Some(status_list) = status.get("status_list").and_then(Value::as_object) else {
        return false;
    };
    status_list.len() == 2
        && status_list.get("idx").is_some_and(Value::is_u64)
        && status_list.get("uri").is_some_and(Value::is_string)
}

fn verify_oid4vp_token_status(
    credential_payload: &Value,
    resolver: &impl HttpResolver,
    trust_anchors_der_base64: &[String],
    now_unix_seconds: i64,
) -> CoreResult<()> {
    let Some(status) = credential_payload.get("status") else {
        return Ok(());
    };
    let status_list = status
        .as_object()
        .and_then(|status| status.get("status_list"))
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::StatusCheckFailed,
                "OIDF credential status must contain one status_list reference",
            )
        })?;
    let index = status_list
        .get("idx")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::StatusCheckFailed,
                "OIDF status_list idx must be a non-negative integer",
            )
        })?;
    let uri = status_list
        .get("uri")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::StatusCheckFailed,
                "OIDF status_list uri must be a string",
            )
        })?;
    validate_oid4vp_status_uri(uri)?;
    if trust_anchors_der_base64.is_empty() {
        return Err(CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "OIDF status list cannot be accepted without a trust anchor",
        ));
    }

    let resolved = resolver.resolve(uri).map_err(|_| {
        CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "OIDF status list could not be resolved",
        )
    })?;
    if resolved.is_empty() || resolved.len() as u64 > OID4VP_MAX_STATUS_LIST_BYTES {
        return Err(CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "OIDF status-list token exceeds its bounded size",
        ));
    }
    let compact_jws = std::str::from_utf8(&resolved).map_err(|_| {
        CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "OIDF status-list resolver returned non-UTF-8 bytes",
        )
    })?;
    let header_segment = compact_jws.split('.').next().ok_or_else(|| {
        CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "OIDF status-list response is not a compact JWS",
        )
    })?;
    let unverified_header: JwsHeader = decode_json_segment(header_segment).map_err(|_| {
        CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "OIDF status-list JWS header is malformed",
        )
    })?;
    if unverified_header.typ.as_deref() != Some(OID4VP_STATUS_LIST_TYP) {
        return Err(CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "OIDF status-list JWS typ must be statuslist+jwt",
        ));
    }
    let certificate_chain = unverified_header.x5c.as_ref().ok_or_else(|| {
        CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "OIDF status-list JWS must contain an x5c certificate path",
        )
    })?;
    let validated = validate_oid4vp_x509_signing_chain(
        certificate_chain,
        trust_anchors_der_base64,
        now_unix_seconds,
    )
    .map_err(|_| {
        CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "OIDF status-list signing certificate path is not trusted or current",
        )
    })?;
    let verified = verify_compact_jws(compact_jws, &validated.public_jwk).map_err(|_| {
        CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "OIDF status-list JWS signature is invalid",
        )
    })?;
    let payload: Value = serde_json::from_slice(&verified.payload).map_err(|_| {
        CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "OIDF status-list JWS payload is malformed",
        )
    })?;
    if payload.get("sub").and_then(Value::as_str) != Some(uri) {
        return Err(CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "OIDF status-list token subject does not match its resolved URI",
        ));
    }
    let issued_at = oid4vp_status_numeric_date(&payload, "iat", true)?.expect("iat is required");
    if issued_at > now_unix_seconds as f64 + DEFAULT_MAX_KB_FUTURE_SKEW_SECONDS as f64 {
        return Err(CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "OIDF status-list token was issued in the future",
        ));
    }
    if oid4vp_status_numeric_date(&payload, "exp", false)?
        .is_some_and(|expires_at| expires_at <= now_unix_seconds as f64)
    {
        return Err(CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "OIDF status-list token is expired",
        ));
    }
    if oid4vp_status_numeric_date(&payload, "ttl", false)?.is_some_and(|ttl| ttl <= 0.0) {
        return Err(CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "OIDF status-list token ttl must be positive",
        ));
    }

    let encoded_list = payload
        .get("status_list")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::StatusCheckFailed,
                "OIDF status-list token is missing status_list",
            )
        })?;
    let bits = encoded_list
        .get("bits")
        .and_then(Value::as_u64)
        .filter(|bits| matches!(bits, 1 | 2 | 4 | 8))
        .ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::StatusCheckFailed,
                "OIDF status-list bits must be one of 1, 2, 4, or 8",
            )
        })?;
    let compressed = encoded_list
        .get("lst")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::StatusCheckFailed,
                "OIDF status-list token lst must be a string",
            )
        })
        .and_then(|value| {
            b64_decode(value).map_err(|_| {
                CoreError::new(
                    CoreErrorCode::StatusCheckFailed,
                    "OIDF status-list lst is not unpadded base64url",
                )
            })
        })?;
    let mut decoded = Vec::new();
    ZlibDecoder::new(compressed.as_slice())
        .take(OID4VP_MAX_STATUS_LIST_BYTES + 1)
        .read_to_end(&mut decoded)
        .map_err(|_| {
            CoreError::new(
                CoreErrorCode::StatusCheckFailed,
                "OIDF status-list lst is not valid zlib-compressed data",
            )
        })?;
    if decoded.is_empty() || decoded.len() as u64 > OID4VP_MAX_STATUS_LIST_BYTES {
        return Err(CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "OIDF status-list decoded payload exceeds its bounded size",
        ));
    }
    let bit_index = index.checked_mul(bits).ok_or_else(|| {
        CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "OIDF status-list index exceeds its bounded range",
        )
    })?;
    let byte_index = usize::try_from(bit_index / 8).map_err(|_| {
        CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "OIDF status-list index exceeds its bounded range",
        )
    })?;
    let value = decoded.get(byte_index).ok_or_else(|| {
        CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "OIDF status-list index is outside the decoded list",
        )
    })?;
    let shift = u32::try_from(bit_index % 8).expect("status-list shift is below eight");
    let mask = u8::try_from((1_u16 << bits) - 1).expect("status-list mask fits in one byte");
    if (*value >> shift) & mask != 0 {
        return Err(CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "OIDF credential status is not valid",
        ));
    }
    Ok(())
}

fn validate_oid4vp_status_uri(value: &str) -> CoreResult<()> {
    let parsed = Url::parse(value).map_err(|_| {
        CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "OIDF status-list URI is invalid",
        )
    })?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "OIDF status-list URI must be absolute HTTPS without credentials or a fragment",
        ));
    }
    Ok(())
}

fn oid4vp_status_numeric_date(
    payload: &Value,
    name: &str,
    required: bool,
) -> CoreResult<Option<f64>> {
    match payload.get(name) {
        None if !required => Ok(None),
        Some(Value::Number(number)) => number
            .as_f64()
            .filter(|value| value.is_finite())
            .map(Some)
            .ok_or_else(|| {
                CoreError::new(
                    CoreErrorCode::StatusCheckFailed,
                    format!("OIDF status-list {name} is not a finite NumericDate"),
                )
            }),
        _ => Err(CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            format!("OIDF status-list {name} is not a finite NumericDate"),
        )),
    }
}

/// Verify an issuer SD-JWT credential without a KB-JWT.
///
/// This is used by the conformance gate and interop slices where the artifact
/// under test is the credential envelope itself rather than a holder-bound
/// presentation.
pub fn verify_sd_jwt_credential(
    compact_sd_jwt: &str,
    issuer_jwk: &PublicJwk,
    options: &SdJwtCredentialVerificationOptions,
) -> CoreResult<VerifiedSdJwtCredential> {
    let (issuer_jwt, disclosures, kb_jwt) = split_sd_jwt(compact_sd_jwt)?;
    if kb_jwt.is_some() {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "expected issuer SD-JWT credential without KB-JWT",
        ));
    }
    verify_and_materialize_sd_jwt(
        issuer_jwt,
        &disclosures,
        issuer_jwk,
        Some(options.format.expected_typ()),
        options.now_unix_seconds,
        &options.required_claims,
    )
}

fn validate_w3c_vc_jwt_claims(payload: &Value) -> CoreResult<()> {
    let object = payload.as_object().ok_or_else(|| {
        CoreError::new(
            CoreErrorCode::InvalidInput,
            "W3C VC SD-JWT payload must be an object",
        )
    })?;
    if object.contains_key("vc") || object.contains_key("vp") {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "W3C VC SD-JWT payload must not contain vc or vp JWT claims",
        ));
    }
    if let Some(iss) = object.get("iss") {
        let iss = iss.as_str().ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::InvalidInput,
                "W3C VC SD-JWT iss claim must be a string when present",
            )
        })?;
        let issuer = match object.get("issuer") {
            Some(Value::String(issuer)) => Some(issuer.as_str()),
            Some(Value::Object(issuer)) => issuer.get("id").and_then(Value::as_str),
            _ => None,
        };
        if issuer != Some(iss) {
            return Err(CoreError::new(
                CoreErrorCode::InvalidInput,
                "W3C VC SD-JWT iss claim must match credential issuer",
            ));
        }
    }
    if let Some(jti) = object.get("jti") {
        let jti = jti.as_str().ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::InvalidInput,
                "W3C VC SD-JWT jti claim must be a string when present",
            )
        })?;
        if object
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| id != jti)
        {
            return Err(CoreError::new(
                CoreErrorCode::InvalidInput,
                "W3C VC SD-JWT jti claim must match credential id",
            ));
        }
    }
    if let Some(sub) = object.get("sub") {
        let sub = sub.as_str().ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::InvalidInput,
                "W3C VC SD-JWT sub claim must be a string when present",
            )
        })?;
        let subject_ids = match object.get("credentialSubject") {
            Some(Value::Object(subject)) => subject
                .get("id")
                .and_then(Value::as_str)
                .into_iter()
                .collect::<Vec<_>>(),
            Some(Value::Array(subjects)) => subjects
                .iter()
                .filter_map(|subject| subject.get("id").and_then(Value::as_str))
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        };
        if !subject_ids.is_empty() && !subject_ids.contains(&sub) {
            return Err(CoreError::new(
                CoreErrorCode::InvalidInput,
                "W3C VC SD-JWT sub claim must identify a credential subject",
            ));
        }
    }
    Ok(())
}

fn validate_w3c_vc_jose_header(
    format: CredentialFormat,
    header: &JwsHeader,
    payload: &Value,
) -> CoreResult<()> {
    if format != CredentialFormat::W3cVcDataModel {
        return Ok(());
    }
    if header.cty.as_deref().is_some_and(|cty| cty != "vc") {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "W3C VC SD-JWT cty must be vc when present",
        ));
    }
    if payload.get("iss").is_some() {
        return Ok(());
    }
    let kid = header.kid.as_deref().ok_or_else(|| {
        CoreError::new(
            CoreErrorCode::InvalidInput,
            "W3C VC SD-JWT kid is required when iss is absent",
        )
    })?;
    if Url::parse(kid).is_err() {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "W3C VC SD-JWT kid must be an absolute URL when iss is absent",
        ));
    }
    Ok(())
}

fn validate_w3c_vc_disclosure_specs(
    format: CredentialFormat,
    disclosure_specs: &[DisclosureSpec],
) -> CoreResult<()> {
    if format != CredentialFormat::W3cVcDataModel {
        return Ok(());
    }
    const NON_SELECTIVE_PROPERTIES: &[&str] = &[
        "@context",
        "type",
        "issuer",
        "credentialSubject",
        "credentialStatus",
        "credentialSchema",
        "relatedResource",
        "validFrom",
        "validUntil",
        "iss",
        "cnf",
    ];
    for spec in disclosure_specs {
        let root = spec
            .object_path
            .first()
            .map(String::as_str)
            .unwrap_or(spec.claim_name.as_str());
        if NON_SELECTIVE_PROPERTIES.contains(&root)
            && (root != "credentialSubject" || spec.object_path.is_empty())
        {
            return Err(CoreError::new(
                CoreErrorCode::InvalidInput,
                format!("W3C VC validation property must not be selectively disclosable: {root}"),
            ));
        }
    }
    Ok(())
}

fn verify_and_materialize_sd_jwt(
    issuer_jwt: &str,
    disclosures: &[&str],
    issuer_jwk: &PublicJwk,
    expected_typ: Option<&str>,
    now_unix_seconds: i64,
    required_claims: &[Vec<String>],
) -> CoreResult<VerifiedSdJwtCredential> {
    let verified_issuer = verify_compact_jws(issuer_jwt, issuer_jwk)?;
    if let Some(expected_typ) = expected_typ {
        if verified_issuer.header.typ.as_deref() != Some(expected_typ) {
            return Err(CoreError::new(
                CoreErrorCode::VerificationFailed,
                format!("issuer JWT typ must be {expected_typ}"),
            ));
        }
    }

    let mut payload: Value =
        serde_json::from_slice(&verified_issuer.payload).map_err(json_error)?;
    ensure_sd_alg(&payload)?;
    ensure_issuer_jwt_validity(&payload, now_unix_seconds)?;

    let disclosures = disclosures
        .iter()
        .map(|disclosure| decode_disclosure(disclosure))
        .collect::<CoreResult<Vec<_>>>()?;
    let disclosed_claim_paths = apply_disclosures(&mut payload, &disclosures)?;

    for claim_path in required_claims {
        if value_at_path(&payload, claim_path).is_none() {
            return Err(CoreError::new(
                CoreErrorCode::MissingDisclosure,
                format!("required disclosure missing: {}", claim_path.join(".")),
            ));
        }
    }

    let format = match verified_issuer.header.typ.as_deref() {
        Some(VC_SD_JWT_TYP) => Some(CredentialFormat::W3cVcDataModel),
        Some(DC_SD_JWT_TYP) => Some(CredentialFormat::IetfSdJwtVc),
        _ => None,
    };
    if let Some(format) = format {
        format.validate_payload(&payload)?;
        validate_w3c_vc_jose_header(format, &verified_issuer.header, &payload)?;
    }

    Ok(VerifiedSdJwtCredential {
        issuer_header: verified_issuer.header,
        processed_payload: payload,
        disclosed_claim_paths,
    })
}

/// Verify compact JWS with an ES256 P-256 public JWK.
pub fn verify_compact_jws(compact_jws: &str, public_jwk: &PublicJwk) -> CoreResult<VerifiedJws> {
    let parts: Vec<&str> = compact_jws.split('.').collect();
    if parts.len() != 3 {
        return Err(CoreError::new(
            CoreErrorCode::MalformedJws,
            "compact JWS must have exactly three dot-separated parts",
        ));
    }

    let header_value: serde_json::Value = decode_json_segment(parts[0])?;
    if header_value.get("crit").is_some() {
        return Err(CoreError::new(
            CoreErrorCode::UnsupportedAlgorithm,
            "compact JWS critical header extensions are unsupported",
        ));
    }
    let header: JwsHeader = serde_json::from_value(header_value).map_err(json_error)?;
    if header.alg != "ES256" {
        return Err(CoreError::new(
            CoreErrorCode::UnsupportedAlgorithm,
            "compact JWS alg must be ES256",
        ));
    }

    let payload = b64_decode(parts[1])?;
    let signature = b64_decode(parts[2])?;
    let signature = Signature::from_slice(&signature).map_err(|_| {
        CoreError::new(
            CoreErrorCode::InvalidSignature,
            "ES256 signature must be 64 raw bytes",
        )
    })?;
    let verifying_key = verifying_key_from_jwk(public_jwk)?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);

    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| CoreError::new(CoreErrorCode::InvalidSignature, "signature check failed"))?;

    Ok(VerifiedJws { header, payload })
}

/// Verify compact JWS and deserialize the payload.
pub fn verify_compact_jws_json<T: DeserializeOwned>(
    compact_jws: &str,
    public_jwk: &PublicJwk,
) -> CoreResult<(JwsHeader, T)> {
    let verified = verify_compact_jws(compact_jws, public_jwk)?;
    let payload = serde_json::from_slice(&verified.payload).map_err(json_error)?;
    Ok((verified.header, payload))
}

/// Verify an RFC 9449 DPoP proof and its request/access-token binding.
pub fn verify_dpop_proof(
    compact_jws: &str,
    options: &DpopVerificationOptions,
) -> CoreResult<VerifiedDpopProof> {
    if options.max_age_seconds <= 0 || options.max_age_seconds > 600 {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "DPoP maximum age must be between 1 and 600 seconds",
        ));
    }
    if options.expected_htu.is_empty() || !is_uppercase_http_method(&options.expected_htm) {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "DPoP expected HTTP URI and uppercase method are required",
        ));
    }

    let parts: Vec<&str> = compact_jws.split('.').collect();
    if parts.len() != 3 {
        return Err(CoreError::new(
            CoreErrorCode::MalformedJws,
            "DPoP proof must have exactly three dot-separated parts",
        ));
    }
    let unverified_header_value: serde_json::Value = decode_json_segment(parts[0])?;
    let unverified_jwk = unverified_header_value
        .get("jwk")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::InvalidKey,
                "DPoP proof header must contain a public JWK",
            )
        })?;
    if ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
        .iter()
        .any(|member| unverified_jwk.contains_key(*member))
    {
        return Err(CoreError::new(
            CoreErrorCode::InvalidKey,
            "DPoP proof header JWK must not contain private key material",
        ));
    }
    let unverified_header: JwsHeader =
        serde_json::from_value(unverified_header_value).map_err(json_error)?;
    let public_jwk = unverified_header.jwk.clone().ok_or_else(|| {
        CoreError::new(
            CoreErrorCode::InvalidKey,
            "DPoP proof header must contain a public JWK",
        )
    })?;
    let (header, claims): (JwsHeader, DpopClaims) =
        verify_compact_jws_json(compact_jws, &public_jwk)?;

    if header.typ.as_deref() != Some("dpop+jwt") {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "DPoP proof typ must be dpop+jwt",
        ));
    }
    if normalized_dpop_htu(&claims.htu)? != normalized_dpop_htu(&options.expected_htu)?
        || !is_uppercase_http_method(&claims.htm)
        || claims.htm != options.expected_htm
    {
        return Err(CoreError::new(
            CoreErrorCode::BindingCheckFailed,
            "DPoP proof HTTP method or URI binding failed",
        ));
    }
    if claims.jti.is_empty() || claims.jti.len() > 512 {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "DPoP proof jti must be non-empty and bounded",
        ));
    }
    if claims.iat > options.now_unix_seconds + DEFAULT_DPOP_FUTURE_SKEW_SECONDS
        || options.now_unix_seconds - claims.iat > options.max_age_seconds
    {
        return Err(CoreError::new(
            CoreErrorCode::FreshnessCheckFailed,
            "DPoP proof issued-at time is outside the accepted window",
        ));
    }

    if let Some(access_token) = options.access_token.as_deref() {
        let expected_ath = sha256_b64url(access_token.as_bytes());
        if claims.ath.as_deref() != Some(expected_ath.as_str()) {
            return Err(CoreError::new(
                CoreErrorCode::BindingCheckFailed,
                "DPoP proof access-token hash binding failed",
            ));
        }
    }
    if let Some(expected_nonce) = options.expected_nonce.as_deref()
        && claims.nonce.as_deref() != Some(expected_nonce)
    {
        return Err(CoreError::new(
            CoreErrorCode::BindingCheckFailed,
            "DPoP proof nonce binding failed",
        ));
    }

    Ok(VerifiedDpopProof {
        public_jwk_sha256_thumbprint: public_jwk_sha256_thumbprint(&public_jwk)?,
        public_jwk,
        htu: claims.htu,
        htm: claims.htm,
        iat: claims.iat,
        jti: claims.jti,
    })
}

fn is_uppercase_http_method(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_uppercase()
                || byte.is_ascii_digit()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn normalized_dpop_htu(value: &str) -> CoreResult<String> {
    let without_fragment = value.split_once('#').map_or(value, |(prefix, _)| prefix);
    let without_query = without_fragment
        .split_once('?')
        .map_or(without_fragment, |(prefix, _)| prefix);
    let (scheme, remainder) = without_query.split_once("://").ok_or_else(|| {
        CoreError::new(
            CoreErrorCode::InvalidInput,
            "DPoP HTTP URI must be absolute",
        )
    })?;
    if !scheme.eq_ignore_ascii_case("https") && !scheme.eq_ignore_ascii_case("http") {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "DPoP HTTP URI scheme must be http or https",
        ));
    }

    let authority_end = remainder.find('/').unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    if authority.is_empty() || authority.contains('@') || authority.chars().any(char::is_whitespace)
    {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "DPoP HTTP URI authority is invalid",
        ));
    }
    let scheme = scheme.to_ascii_lowercase();
    let mut authority = authority.to_ascii_lowercase();
    let default_port = if scheme == "https" { ":443" } else { ":80" };
    if authority.ends_with(default_port) {
        authority.truncate(authority.len() - default_port.len());
    }
    let path = if authority_end == remainder.len() {
        "/"
    } else {
        &remainder[authority_end..]
    };
    if path.chars().any(char::is_whitespace) {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "DPoP HTTP URI path is invalid",
        ));
    }
    Ok(format!("{scheme}://{authority}{path}"))
}

/// Verify an OAuth client attestation and the per-request proof signed by its client-instance key.
pub fn verify_client_attestation(
    client_attestation_jwt: &str,
    client_attestation_pop_jwt: &str,
    options: &ClientAttestationVerificationOptions,
) -> CoreResult<VerifiedClientAttestation> {
    if options.max_age_seconds <= 0 || options.max_age_seconds > 600 {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "client-attestation maximum age must be between 1 and 600 seconds",
        ));
    }
    if options.expected_attester_issuer.is_empty()
        || options
            .expected_client_id
            .as_deref()
            .is_some_and(str::is_empty)
        || options.expected_audience.is_empty()
    {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "client-attestation issuer and audience are required",
        ));
    }

    let (attestation_header, attestation): (JwsHeader, ClientAttestationClaims) =
        verify_compact_jws_json(client_attestation_jwt, &options.trusted_attester_jwk)?;
    if attestation_header.typ.as_deref() != Some("oauth-client-attestation+jwt") {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "client-attestation typ is invalid",
        ));
    }
    let client_id = attestation
        .sub
        .as_deref()
        .filter(|value| !value.is_empty() && value.len() <= 2048)
        .ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::InvalidInput,
                "client-attestation subject must be non-empty and bounded",
            )
        })?;
    if attestation.iss != options.expected_attester_issuer
        || options
            .expected_client_id
            .as_deref()
            .is_some_and(|expected| expected != client_id)
    {
        return Err(CoreError::new(
            CoreErrorCode::BindingCheckFailed,
            "client-attestation issuer or subject binding failed",
        ));
    }
    ensure_attestation_time_window(attestation.iat, attestation.nbf, attestation.exp, options)?;
    let instance_thumbprint = public_jwk_sha256_thumbprint(&attestation.cnf.jwk)?;

    let (proof_header, proof): (JwsHeader, ClientAttestationProofClaims) =
        verify_compact_jws_json(client_attestation_pop_jwt, &attestation.cnf.jwk)?;
    if proof_header.typ.as_deref() != Some("oauth-client-attestation-pop+jwt") {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "client-attestation proof typ is invalid",
        ));
    }
    if proof.iss != client_id || proof.aud != options.expected_audience {
        return Err(CoreError::new(
            CoreErrorCode::BindingCheckFailed,
            "client-attestation proof client or audience binding failed",
        ));
    }
    if proof.jti.is_empty() || proof.jti.len() > 512 {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "client-attestation proof jti must be non-empty and bounded",
        ));
    }
    if let Some(expected_challenge) = options.expected_challenge.as_deref()
        && proof.challenge.as_deref() != Some(expected_challenge)
    {
        return Err(CoreError::new(
            CoreErrorCode::BindingCheckFailed,
            "client-attestation proof challenge binding failed",
        ));
    }
    ensure_attestation_time_window(proof.iat, proof.nbf, proof.exp, options)?;

    Ok(VerifiedClientAttestation {
        client_id: client_id.to_owned(),
        client_instance_jwk: attestation.cnf.jwk,
        client_instance_jwk_sha256_thumbprint: instance_thumbprint,
        attestation_issued_at: attestation.iat,
        proof_issued_at: proof.iat,
        proof_jti: proof.jti,
    })
}

fn ensure_attestation_time_window(
    issued_at: i64,
    not_before: Option<i64>,
    expires_at: i64,
    options: &ClientAttestationVerificationOptions,
) -> CoreResult<()> {
    if issued_at > options.now_unix_seconds + DEFAULT_MAX_KB_FUTURE_SKEW_SECONDS
        || options.now_unix_seconds - issued_at > options.max_age_seconds
        || not_before.is_some_and(|value| {
            value > options.now_unix_seconds + DEFAULT_MAX_KB_FUTURE_SKEW_SECONDS
        })
        || expires_at < options.now_unix_seconds
        || expires_at <= issued_at
    {
        return Err(CoreError::new(
            CoreErrorCode::FreshnessCheckFailed,
            "client-attestation time window is invalid",
        ));
    }
    Ok(())
}

/// Convert a host name to a `did:web` identifier.
///
/// Domain dots stay dots; only a host:port separator is percent encoded as
/// required by the did:web method. Path-form DIDs are handled by
/// `did_web_to_https_url` after the DID is created.
pub fn did_web_from_host(host: &str) -> CoreResult<String> {
    let host = host.trim().to_ascii_lowercase();
    if host.is_empty() || host.contains('/') || host.contains(char::is_whitespace) {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "did:web host must be a non-empty host[:port] without paths",
        ));
    }

    Ok(format!(
        "{DID_WEB_METHOD_PREFIX}{}",
        host.replacen(':', "%3A", 1)
    ))
}

/// Resolve a `did:web` identifier to the HTTPS URL that should serve did.json.
pub fn did_web_to_https_url(did: &str) -> CoreResult<String> {
    let method_specific_id = did.strip_prefix(DID_WEB_METHOD_PREFIX).ok_or_else(|| {
        CoreError::new(
            CoreErrorCode::InvalidInput,
            "DID must use the did:web method",
        )
    })?;
    if method_specific_id.is_empty() {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "did:web method-specific id is empty",
        ));
    }

    let mut parts = method_specific_id.split(':');
    let host = parts
        .next()
        .expect("split always yields at least one item")
        .replace("%3A", ":")
        .replace("%3a", ":");
    if host.is_empty() {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "did:web host is empty",
        ));
    }
    let path: Vec<&str> = parts.collect();
    if path.iter().any(|component| component.is_empty()) {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "did:web path components must be non-empty",
        ));
    }

    let mut url = format!("https://{host}");
    if path.is_empty() {
        url.push_str("/.well-known");
    } else {
        for component in path {
            url.push('/');
            url.push_str(component);
        }
    }
    url.push_str("/did.json");
    Ok(url)
}

/// Return the five planned issuer DIDs under a configured base domain.
pub fn planned_issuer_did_web_identities(base_domain: &str) -> CoreResult<Vec<PlannedIssuerDid>> {
    let base_domain = base_domain.trim().to_ascii_lowercase();
    if base_domain.is_empty()
        || base_domain == "localhost"
        || base_domain.ends_with(".localhost")
        || base_domain.contains('/')
        || base_domain.contains(char::is_whitespace)
    {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "base domain must be a registered DNS name, not localhost",
        ));
    }

    [
        (
            "student",
            "UNSW Registry / mock SIS",
            "issuer.unsw",
            "UniversityEducationCredential",
        ),
        (
            "hr",
            "UNSW HR / mock Workday",
            "hr.unsw",
            "StaffAffiliationCredential",
        ),
        (
            "exams",
            "UNSW Exams Office",
            "exams.unsw",
            "RoleAuthorityCredential",
        ),
        (
            "homeAffairs",
            "Mock Home Affairs",
            "home-affairs.gov",
            "VisaWorkRightsCredential",
        ),
        (
            "governmentIdentity",
            "Mock DFAT / Service NSW",
            "identity.gov",
            "GovernmentIdentityCredential",
        ),
    ]
    .into_iter()
    .map(|(key, label, host_prefix, credential_type)| {
        let host = format!("{host_prefix}.{base_domain}");
        Ok(PlannedIssuerDid {
            key: key.to_owned(),
            label: label.to_owned(),
            did: did_web_from_host(&host)?,
            host,
            credential_types: vec![credential_type.to_owned()],
        })
    })
    .collect()
}

/// Build a did:web DID document containing P-256 publicKeyJwk methods.
pub fn build_did_web_document(did: &str, public_jwks: &[PublicJwk]) -> CoreResult<DidDocument> {
    ensure_did_web(did)?;
    if public_jwks.is_empty() {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "DID document must contain at least one verification method",
        ));
    }

    let mut verification_method = Vec::with_capacity(public_jwks.len());
    for (index, jwk) in public_jwks.iter().enumerate() {
        verifying_key_from_jwk(jwk)?;
        let id = did_method_id(did, jwk.kid.as_deref(), index);
        verification_method.push(DidVerificationMethod {
            id,
            type_: DID_VERIFICATION_METHOD_TYPE.to_owned(),
            controller: did.to_owned(),
            public_key_jwk: jwk.clone(),
        });
    }
    let method_ids: Vec<String> = verification_method
        .iter()
        .map(|method| method.id.clone())
        .collect();

    Ok(DidDocument {
        context: vec![DID_CONTEXT.to_owned()],
        id: did.to_owned(),
        verification_method,
        assertion_method: method_ids.clone(),
        authentication: method_ids,
    })
}

/// Resolve a did:web document through the injected resolver.
pub fn resolve_did_web_document(
    did: &str,
    resolver: &impl HttpResolver,
) -> CoreResult<DidDocument> {
    let url = did_web_to_https_url(did)?;
    let body = resolver.resolve(&url)?;
    let document: DidDocument = serde_json::from_slice(&body).map_err(json_error)?;
    if document.id != did {
        return Err(CoreError::new(
            CoreErrorCode::VerificationFailed,
            "did:web document id does not match the resolved DID",
        ));
    }
    Ok(document)
}

/// Resolve the public key for an issuer DID and JWS `kid`.
pub fn resolve_did_web_key(
    issuer_did: &str,
    kid: &str,
    resolver: &impl HttpResolver,
) -> CoreResult<PublicJwk> {
    let document = resolve_did_web_document(issuer_did, resolver)?;
    let candidates = did_kid_candidates(issuer_did, kid);
    let mut matches = document.verification_method.into_iter().filter(|method| {
        let jwk_kid = method.public_key_jwk.kid.as_deref();
        candidates.iter().any(|candidate| candidate == &method.id)
            || jwk_kid
                .is_some_and(|jwk_kid| candidates.iter().any(|candidate| candidate == jwk_kid))
    });
    let Some(method) = matches.next() else {
        return Err(CoreError::new(
            CoreErrorCode::KeyNotFound,
            format!("did:web verification method not found for kid {kid}"),
        ));
    };
    if matches.next().is_some() {
        return Err(CoreError::new(
            CoreErrorCode::KeyNotFound,
            format!("did:web verification method is ambiguous for kid {kid}"),
        ));
    }
    if method.type_ != DID_VERIFICATION_METHOD_TYPE || method.controller != issuer_did {
        return Err(CoreError::new(
            CoreErrorCode::InvalidKey,
            "did:web verification method must be a JsonWebKey controlled by its issuer",
        ));
    }
    verifying_key_from_jwk(&method.public_key_jwk)?;
    Ok(method.public_key_jwk)
}

/// Verify a compact JWS whose payload `iss` is a did:web issuer.
pub fn verify_compact_jws_with_did_web_issuer(
    compact_jws: &str,
    resolver: &impl HttpResolver,
) -> CoreResult<VerifiedJws> {
    let issuer_jwk = resolve_issuer_key_for_jws(compact_jws, resolver)?;
    verify_compact_jws(compact_jws, &issuer_jwk)
}

/// Verify the signed Request Object used by this ecosystem's OID4VP 1.0 flow.
///
/// This is the fail-closed protocol boundary shared by wallet bindings. Key
/// resolution follows the `decentralized_identifier` client-id scheme and the
/// protected `kid`, never the optional JWT `iss` claim.
pub fn verify_oid4vp_request_object(
    compact_jws: &str,
    resolver: &impl HttpResolver,
    now_unix_seconds: i64,
) -> CoreResult<VerifiedOid4vpRequest> {
    let parts = compact_jws.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(CoreError::new(
            CoreErrorCode::MalformedJws,
            "OID4VP Request Object must be a compact JWS",
        ));
    }
    let unverified_header: JwsHeader = decode_json_segment(parts[0])?;
    let kid = unverified_header.kid.as_deref().ok_or_else(|| {
        CoreError::new(
            CoreErrorCode::KeyNotFound,
            "OID4VP Request Object header is missing kid",
        )
    })?;
    let unverified_payload = decode_jws_payload_unverified(compact_jws)?;
    let client_id = oid4vp_required_string(&unverified_payload, "client_id")?;
    let verifier_did = client_id
        .strip_prefix(OID4VP_DECENTRALIZED_IDENTIFIER_PREFIX)
        .ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::VerificationFailed,
                "OID4VP client_id must use decentralized_identifier prefix",
            )
        })?;
    did_web_to_https_url(verifier_did).map_err(|_| {
        CoreError::new(
            CoreErrorCode::VerificationFailed,
            "OID4VP decentralized_identifier client_id must contain a did:web DID",
        )
    })?;
    let verifier_jwk = resolve_did_web_key(verifier_did, kid, resolver)?;
    let (header, payload): (JwsHeader, Value) =
        verify_compact_jws_json(compact_jws, &verifier_jwk)?;

    if header.typ.as_deref() != Some(OID4VP_REQUEST_TYP) {
        return Err(CoreError::new(
            CoreErrorCode::VerificationFailed,
            "OID4VP Request Object typ must be oauth-authz-req+jwt",
        ));
    }
    validate_oid4vp_request_payload(&payload, now_unix_seconds)?;

    Ok(VerifiedOid4vpRequest {
        header,
        payload,
        verifier_did: verifier_did.to_owned(),
    })
}

/// Verify the pinned OIDF wallet-presentation request without broadening the
/// first-party verifier policy above.
///
/// The official wallet plan omits JWT time claims, so replay prevention is a
/// ceremony concern enforced by the caller after this function returns. This
/// boundary authenticates the exact request, outer activation, response
/// destination, metadata, DCQL and HAIP encryption key before consent.
pub fn verify_oid4vp_wallet_interop_request(
    compact_jws: &str,
    verifier_jwk: &PublicJwk,
    policy: &Oid4vpWalletRequestPolicy,
) -> CoreResult<VerifiedOid4vpWalletInteropRequest> {
    if compact_jws.len() > 1_048_576 {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "OIDF wallet Request Object exceeds the bounded size",
        ));
    }
    let (header, payload): (JwsHeader, Value) = verify_compact_jws_json(compact_jws, verifier_jwk)?;
    if header.typ.as_deref() != Some(OID4VP_REQUEST_TYP) {
        return Err(CoreError::new(
            CoreErrorCode::VerificationFailed,
            "OIDF wallet Request Object typ must be oauth-authz-req+jwt",
        ));
    }
    if !is_strict_https_uri(&policy.request_uri)
        || uri_origin(&policy.request_uri).as_deref() != Some(policy.expected_origin.as_str())
    {
        return Err(CoreError::new(
            CoreErrorCode::VerificationFailed,
            "OIDF wallet request_uri is outside the trusted suite origin",
        ));
    }
    let client_id = oid4vp_required_string(&payload, "client_id")?;
    if client_id != policy.activation_client_id || client_id != policy.expected_client_id {
        return Err(CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "OIDF wallet client identity is not bound to the activation and pinned verifier",
        ));
    }
    match policy.profile {
        Oid4vpWalletInteropProfile::Final => {
            if !client_id.starts_with("decentralized_identifier:did:jwk:") || header.x5c.is_some() {
                return Err(CoreError::new(
                    CoreErrorCode::TrustCheckFailed,
                    "OIDF Final wallet request must use the pinned decentralized identifier",
                ));
            }
        }
        Oid4vpWalletInteropProfile::Haip => {
            let expected_chain = policy.expected_x5c.as_ref().ok_or_else(|| {
                CoreError::new(
                    CoreErrorCode::TrustCheckFailed,
                    "OIDF HAIP verifier certificate trust is unavailable",
                )
            })?;
            let chain = header.x5c.as_ref().ok_or_else(|| {
                CoreError::new(
                    CoreErrorCode::TrustCheckFailed,
                    "OIDF HAIP Request Object is missing x5c",
                )
            })?;
            let leaf = expected_chain.first().ok_or_else(|| {
                CoreError::new(
                    CoreErrorCode::TrustCheckFailed,
                    "OIDF HAIP verifier certificate chain is empty",
                )
            })?;
            if chain != expected_chain
                || client_id != format!("x509_hash:{}", sha256_b64url(&decode_x5c_leaf(leaf)?))
            {
                return Err(CoreError::new(
                    CoreErrorCode::TrustCheckFailed,
                    "OIDF HAIP Request Object certificate does not authenticate client_id",
                ));
            }
        }
    }

    if !oid4vp_audience_is_self_issued(payload.get("aud"))
        || oid4vp_required_string(&payload, "response_type")? != "vp_token"
    {
        return Err(CoreError::new(
            CoreErrorCode::VerificationFailed,
            "OIDF wallet request audience or response_type is invalid",
        ));
    }
    let expected_mode = match policy.profile {
        Oid4vpWalletInteropProfile::Final => "direct_post",
        Oid4vpWalletInteropProfile::Haip => "direct_post.jwt",
    };
    if oid4vp_required_string(&payload, "response_mode")? != expected_mode {
        return Err(CoreError::new(
            CoreErrorCode::VerificationFailed,
            "OIDF wallet response_mode does not match the selected profile",
        ));
    }
    let response_uri = oid4vp_required_string(&payload, "response_uri")?;
    if !is_strict_https_uri(response_uri)
        || uri_origin(response_uri).as_deref() != Some(policy.expected_origin.as_str())
        || !oidf_suite_response_uri_matches_request(&policy.request_uri, response_uri)
        || payload.get("redirect_uri").is_some()
    {
        return Err(CoreError::new(
            CoreErrorCode::VerificationFailed,
            "OIDF wallet response destination is invalid",
        ));
    }
    let nonce = oid4vp_required_string(&payload, "nonce")?;
    if nonce.len() < 16 || nonce.len() > 128 || !nonce.is_ascii() {
        return Err(CoreError::new(
            CoreErrorCode::FreshnessCheckFailed,
            "OIDF wallet nonce is missing or outside its bounded format",
        ));
    }
    if let Some(state) = payload.get("state") {
        let state = state.as_str().ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::FreshnessCheckFailed,
                "OIDF wallet state must be a string",
            )
        })?;
        if state.is_empty() || state.len() > 256 {
            return Err(CoreError::new(
                CoreErrorCode::FreshnessCheckFailed,
                "OIDF wallet state is outside its bounded format",
            ));
        }
    }
    if payload.get("transaction_data").is_some() {
        return Err(CoreError::new(
            CoreErrorCode::VerificationFailed,
            "OIDF wallet does not recognize the requested transaction_data type",
        ));
    }

    validate_oid4vp_interop_metadata(&payload)?;
    let (credential_selections, dcql_satisfied) = validate_oid4vp_interop_dcql(&payload, policy)?;
    let encryption_key = match policy.profile {
        Oid4vpWalletInteropProfile::Final => None,
        Oid4vpWalletInteropProfile::Haip => Some(select_oid4vp_encryption_key(&payload)?),
    };
    Ok(VerifiedOid4vpWalletInteropRequest {
        payload,
        credential_selections,
        dcql_satisfied,
        encryption_key,
    })
}

/// Encrypt a JSON object for the HAIP `direct_post.jwt` response.
pub fn encrypt_oid4vp_wallet_response(
    plaintext: &Value,
    recipient_jwk: &JwePublicJwk,
) -> CoreResult<String> {
    if !plaintext.is_object() {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "OID4VP response plaintext must be a JSON object",
        ));
    }
    validate_oid4vp_wallet_response_public_key(recipient_jwk)?;
    let ephemeral_secret = random_p256_secret()?;
    let mut iv = [0_u8; OID4VP_JWE_IV_BYTES];
    getrandom::fill(&mut iv).map_err(|error| {
        CoreError::new(
            CoreErrorCode::SigningFailed,
            format!("OS CSPRNG unavailable for OID4VP JWE: {error}"),
        )
    })?;
    encrypt_oid4vp_wallet_response_with_material(plaintext, recipient_jwk, &ephemeral_secret, &iv)
}

fn encrypt_oid4vp_wallet_response_with_material(
    plaintext: &Value,
    recipient_jwk: &JwePublicJwk,
    ephemeral_secret: &SecretKey,
    iv: &[u8; OID4VP_JWE_IV_BYTES],
) -> CoreResult<String> {
    let recipient_public = public_key_from_jwe_jwk(recipient_jwk)?;
    let shared_secret = diffie_hellman(
        ephemeral_secret.to_nonzero_scalar(),
        recipient_public.as_affine(),
    );
    let cek = Zeroizing::new(ecdh_es_concat_kdf_bits(
        shared_secret.raw_secret_bytes().as_slice(),
        OID4VP_JWE_ENC,
        None,
        None,
        256,
    )?);
    let encoded = ephemeral_secret.public_key().to_sec1_point(false);
    let epk = JwePublicJwk {
        kty: "EC".to_owned(),
        crv: "P-256".to_owned(),
        x: b64_encode(encoded.x().expect("uncompressed point has x")),
        y: b64_encode(encoded.y().expect("uncompressed point has y")),
        kid: None,
        alg: None,
        key_use: None,
    };
    let protected = encode_json_segment(&Oid4vpJweHeader {
        alg: OID4VP_JWE_ALG.to_owned(),
        enc: OID4VP_JWE_ENC.to_owned(),
        cty: Some("json".to_owned()),
        crit: None,
        kid: recipient_jwk.kid.clone(),
        epk: Some(epk),
        apu: None,
        apv: None,
    })?;
    let plaintext = Zeroizing::new(serde_json::to_vec(plaintext).map_err(json_error)?);
    if plaintext.len() as u64 > OID4VP_JWE_MAX_PLAINTEXT_BYTES {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "OID4VP JWE plaintext exceeds the bounded size",
        ));
    }
    let cipher = Aes256Gcm::new_from_slice(&cek)
        .map_err(|_| CoreError::new(CoreErrorCode::InvalidKey, "OID4VP JWE key is invalid"))?;
    let mut encrypted = cipher
        .encrypt(
            Nonce::from_slice(iv),
            Payload {
                msg: plaintext.as_slice(),
                aad: protected.as_bytes(),
            },
        )
        .map_err(|_| {
            CoreError::new(CoreErrorCode::SigningFailed, "OID4VP JWE encryption failed")
        })?;
    if encrypted.len() < OID4VP_JWE_TAG_BYTES {
        return Err(CoreError::new(
            CoreErrorCode::SigningFailed,
            "OID4VP JWE omitted its authentication tag",
        ));
    }
    let tag = encrypted.split_off(encrypted.len() - OID4VP_JWE_TAG_BYTES);
    Ok(format!(
        "{protected}..{}.{}.{}",
        b64_encode(iv),
        b64_encode(&encrypted),
        b64_encode(&tag)
    ))
}

/// Verify an SD-JWT+KB presentation whose issuer key is resolved from did:web.
pub fn verify_sd_jwt_presentation_with_did_web(
    presentation: &str,
    resolver: &impl HttpResolver,
    options: &SdJwtVerificationOptions,
) -> CoreResult<VerifiedSdJwtPresentation> {
    let (issuer_jwt, _, _) = split_sd_jwt(presentation)?;
    let issuer_jwk = resolve_issuer_key_for_jws(issuer_jwt, resolver)?;
    verify_sd_jwt_presentation(presentation, &issuer_jwk, options)
}

/// W3C VC Data Model 2.0 payload subset used by the ecosystem.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VerifiableCredentialPayload {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub type_: Vec<String>,
    pub issuer: String,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: Value,
    #[serde(rename = "credentialStatus", skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<CredentialStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Confirmation>,
    #[serde(rename = "validFrom", skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    #[serde(rename = "validUntil", skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
}

/// W3C credential status entry for Bitstring Status List references.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CredentialStatus {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "statusPurpose")]
    pub status_purpose: String,
    #[serde(rename = "statusListIndex")]
    pub status_list_index: String,
    #[serde(rename = "statusListCredential")]
    pub status_list_credential: String,
}

/// W3C Bitstring Status List credential payload secured as compact JWS.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BitstringStatusListCredentialPayload {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub type_: Vec<String>,
    pub issuer: String,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: BitstringStatusListSubject,
    #[serde(rename = "validFrom", skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    #[serde(rename = "validUntil", skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
}

/// Credential subject of a Bitstring Status List credential.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BitstringStatusListSubject {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "statusPurpose")]
    pub status_purpose: String,
    #[serde(rename = "encodedList")]
    pub encoded_list: String,
}

/// Result of resolving a credential's status-list entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CredentialStatusResolution {
    pub status_list_credential: String,
    pub status_list_index: usize,
    pub status_purpose: String,
    pub revoked: bool,
}

/// Size report for a W3C Bitstring Status List.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StatusListSizeReport {
    pub bit_len: usize,
    pub uncompressed_bytes: usize,
    pub encoded_list_bytes: usize,
}

/// Signed trust-list payload used by offline verifiers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrustListPayload {
    pub id: String,
    pub issuer: String,
    pub iat: i64,
    pub exp: i64,
    pub entries: Vec<TrustListEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verifiers: Vec<VerifierTrustListEntry>,
}

/// One issuer accreditation entry in a trust list.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrustListEntry {
    pub issuer_did: String,
    pub credential_types: Vec<String>,
    pub status: TrustListStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_jwk: Option<PublicJwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_jwk_sha256_thumbprint: Option<String>,
}

/// One verifier accreditation scoped to a credential profile and claim paths.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifierTrustListEntry {
    pub verifier_did: String,
    pub credential_type: String,
    pub profile_name: String,
    pub claim_paths: Vec<Vec<String>>,
    pub status: TrustListStatus,
}

/// Accreditation status for an issuer/type scope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustListStatus {
    Active,
    Inactive,
}

/// Result of checking one issuer/type pair against a signed trust list.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrustAccreditationResult {
    pub issuer_did: String,
    pub credential_type: String,
    pub active: bool,
    pub public_jwk_sha256_thumbprint: String,
}

/// Result of checking a verifier's requested disclosure against accreditation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifierTrustAccreditationResult {
    pub verifier_did: String,
    pub credential_type: String,
    pub profile_name: String,
    pub claim_paths: Vec<Vec<String>>,
    pub active: bool,
}

/// JWT confirmation claim carrying the holder public key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Confirmation {
    pub jwk: PublicJwk,
}

/// Compute the RFC 7638-style SHA-256 thumbprint for a public P-256 JWK.
pub fn public_jwk_sha256_thumbprint(public_jwk: &PublicJwk) -> CoreResult<String> {
    verifying_key_from_jwk(public_jwk)?;
    let canonical = format!(
        r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
        public_jwk.crv, public_jwk.kty, public_jwk.x, public_jwk.y
    );
    Ok(b64_encode(&Sha256::digest(canonical.as_bytes())))
}

/// Sign a trust list as compact JWS with the trust-anchor key.
pub fn sign_trust_list(
    payload: &TrustListPayload,
    header: &JwsHeader,
    signer: &impl Signer,
    key_id: &KeyId,
) -> CoreResult<String> {
    validate_trust_list_payload(payload)?;
    if header.typ.as_deref() != Some(TRUST_LIST_TYP) {
        return Err(CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "trust-list JWS typ must be trust-list+jwt",
        ));
    }
    sign_compact_jws_json(header, payload, signer, key_id)
}

/// Verify a signed trust list with the configured trust-anchor public key.
pub fn verify_trust_list(
    compact_jws: &str,
    trust_anchor_jwk: &PublicJwk,
) -> CoreResult<(JwsHeader, TrustListPayload)> {
    let (header, payload): (JwsHeader, Value) =
        verify_compact_jws_json(compact_jws, trust_anchor_jwk)?;
    if header.typ.as_deref() != Some(TRUST_LIST_TYP) {
        return Err(CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "trust-list JWS typ must be trust-list+jwt",
        ));
    }
    let payload: TrustListPayload = serde_json::from_value(payload).map_err(json_error)?;
    validate_trust_list_payload(&payload)?;
    Ok((header, payload))
}

/// Verify the list and answer one offline accreditation query.
pub fn verify_trust_list_accreditation(
    compact_jws: &str,
    trust_anchor_jwk: &PublicJwk,
    issuer_did: &str,
    credential_type: &str,
    issuer_jwk: &PublicJwk,
    now_unix_seconds: i64,
) -> CoreResult<TrustAccreditationResult> {
    let (_, payload) = verify_trust_list(compact_jws, trust_anchor_jwk)?;
    if now_unix_seconds < payload.iat || now_unix_seconds >= payload.exp {
        return Err(CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "trust list is outside its validity window",
        ));
    }

    let entry = payload
        .entries
        .iter()
        .find(|entry| entry.issuer_did == issuer_did)
        .ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::TrustCheckFailed,
                format!("trust list has no entry for issuer {issuer_did}"),
            )
        })?;
    if !entry
        .credential_types
        .iter()
        .any(|allowed| allowed == credential_type)
    {
        return Err(CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            format!("issuer is not accredited for credential type {credential_type}"),
        ));
    }
    if entry.status != TrustListStatus::Active {
        return Err(CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "issuer accreditation is inactive",
        ));
    }

    let actual_thumbprint = public_jwk_sha256_thumbprint(issuer_jwk)?;
    let pinned_thumbprint = pinned_trust_list_thumbprint(entry)?;
    if actual_thumbprint != pinned_thumbprint {
        return Err(CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "issuer public key does not match trust-list pin",
        ));
    }

    Ok(TrustAccreditationResult {
        issuer_did: issuer_did.to_owned(),
        credential_type: credential_type.to_owned(),
        active: true,
        public_jwk_sha256_thumbprint: actual_thumbprint,
    })
}

/// Verify a signed trust list and enforce one verifier disclosure scope.
pub fn verify_verifier_trust_list_accreditation(
    compact_jws: &str,
    trust_anchor_jwk: &PublicJwk,
    verifier_did: &str,
    credential_type: &str,
    profile_name: &str,
    requested_claim_paths: &[Vec<String>],
    now_unix_seconds: i64,
) -> CoreResult<VerifierTrustAccreditationResult> {
    let (_, payload) = verify_trust_list(compact_jws, trust_anchor_jwk)?;
    if now_unix_seconds < payload.iat || now_unix_seconds >= payload.exp {
        return Err(CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "trust list is outside its validity window",
        ));
    }
    let entry = payload
        .verifiers
        .iter()
        .find(|entry| {
            entry.verifier_did == verifier_did
                && entry.credential_type == credential_type
                && entry.profile_name == profile_name
        })
        .ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::TrustCheckFailed,
                format!(
                    "verifier {verifier_did} is not accredited for {credential_type}/{profile_name}"
                ),
            )
        })?;
    if entry.status != TrustListStatus::Active {
        return Err(CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "verifier accreditation is inactive",
        ));
    }
    if requested_claim_paths.is_empty()
        || requested_claim_paths
            .iter()
            .any(|requested| !entry.claim_paths.contains(requested))
    {
        return Err(CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "verifier request exceeds its accredited claim scope",
        ));
    }

    Ok(VerifierTrustAccreditationResult {
        verifier_did: verifier_did.to_owned(),
        credential_type: credential_type.to_owned(),
        profile_name: profile_name.to_owned(),
        claim_paths: requested_claim_paths.to_vec(),
        active: true,
    })
}

/// Encode a W3C Bitstring Status List as GZIP-compressed base64url.
///
/// Bit index 0 is the left-most bit of the first byte, matching the W3C
/// Bitstring Status List v1.0 bit-ordering requirement.
pub fn encode_bitstring_status_list(bit_len: usize, set_indices: &[usize]) -> CoreResult<String> {
    if bit_len < DEFAULT_STATUS_LIST_BITS {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            format!("status list must contain at least {DEFAULT_STATUS_LIST_BITS} bits"),
        ));
    }

    let mut bytes = vec![0_u8; bit_len.div_ceil(8)];
    for &index in set_indices {
        if index >= bit_len {
            return Err(CoreError::new(
                CoreErrorCode::InvalidInput,
                format!("status index {index} is outside {bit_len}-bit list"),
            ));
        }
        set_status_bit(&mut bytes, index, true);
    }

    gzip_base64url(&bytes)
}

/// Decode a W3C Bitstring Status List into its raw bitstring bytes.
pub fn decode_bitstring_status_list(encoded_list: &str) -> CoreResult<Vec<u8>> {
    let compressed = b64_decode(encoded_list)?;
    let mut decoder = GzDecoder::new(compressed.as_slice());
    let mut bytes = Vec::new();
    decoder.read_to_end(&mut bytes).map_err(|error| {
        CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            format!("status list gzip decode failed: {error}"),
        )
    })?;
    if bytes.len() * 8 < DEFAULT_STATUS_LIST_BITS {
        return Err(CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "decoded status list is below the W3C minimum length",
        ));
    }
    Ok(bytes)
}

/// Return whether a status-list bit is set.
pub fn bitstring_status_at(encoded_list: &str, index: usize) -> CoreResult<bool> {
    let bytes = decode_bitstring_status_list(encoded_list)?;
    if index >= bytes.len() * 8 {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            format!("status index {index} is outside decoded status list"),
        ));
    }
    Ok(get_status_bit(&bytes, index))
}

/// Summarise status-list size for docs and sanity checks.
pub fn status_list_size_report(
    bit_len: usize,
    encoded_list: &str,
) -> CoreResult<StatusListSizeReport> {
    Ok(StatusListSizeReport {
        bit_len,
        uncompressed_bytes: bit_len.div_ceil(8),
        encoded_list_bytes: encoded_list.len(),
    })
}

/// Sign a Bitstring Status List credential as compact JWS.
pub fn sign_bitstring_status_list_credential(
    payload: &BitstringStatusListCredentialPayload,
    header: &JwsHeader,
    signer: &impl Signer,
    key_id: &KeyId,
) -> CoreResult<String> {
    validate_status_list_payload(payload)?;
    sign_compact_jws_json(header, payload, signer, key_id)
}

/// Verify a signed Bitstring Status List credential before using its bits.
pub fn verify_bitstring_status_list_credential(
    compact_jws: &str,
    issuer_jwk: &PublicJwk,
) -> CoreResult<(JwsHeader, BitstringStatusListCredentialPayload)> {
    let (header, payload): (JwsHeader, BitstringStatusListCredentialPayload) =
        verify_compact_jws_json(compact_jws, issuer_jwk)?;
    validate_status_list_payload(&payload)?;
    decode_bitstring_status_list(&payload.credential_subject.encoded_list)?;
    Ok((header, payload))
}

/// Verify a signed Bitstring Status List credential and its validity window.
pub fn verify_bitstring_status_list_credential_at(
    compact_jws: &str,
    issuer_jwk: &PublicJwk,
    now_unix_seconds: i64,
) -> CoreResult<(JwsHeader, BitstringStatusListCredentialPayload)> {
    let verified = verify_bitstring_status_list_credential(compact_jws, issuer_jwk)?;
    ensure_status_list_fresh(&verified.1, now_unix_seconds)?;
    Ok(verified)
}

/// Resolve a credential's status entry through an injected resolver.
///
/// The resolver can return cached bytes. This function performs no ambient
/// network I/O and validates the signed status-list credential before reading
/// the bit at `statusListIndex`.
pub fn resolve_credential_status(
    status: &CredentialStatus,
    resolver: &impl HttpResolver,
    status_list_jwk: &PublicJwk,
) -> CoreResult<CredentialStatusResolution> {
    resolve_credential_status_with_time(status, resolver, status_list_jwk, None, None)
}

/// Resolve a credential status entry and reject stale status-list credentials.
///
/// The caller supplies verifier time explicitly so offline verification remains
/// deterministic and testable.
pub fn resolve_credential_status_at(
    status: &CredentialStatus,
    resolver: &impl HttpResolver,
    status_list_jwk: &PublicJwk,
    now_unix_seconds: i64,
) -> CoreResult<CredentialStatusResolution> {
    resolve_credential_status_with_time(
        status,
        resolver,
        status_list_jwk,
        Some(now_unix_seconds),
        None,
    )
}

/// Resolve a fresh credential status entry and bind the signed list to the
/// credential issuer whose key was selected from the trust list.
pub fn resolve_credential_status_at_for_issuer(
    status: &CredentialStatus,
    resolver: &impl HttpResolver,
    status_list_jwk: &PublicJwk,
    expected_issuer: &str,
    now_unix_seconds: i64,
) -> CoreResult<CredentialStatusResolution> {
    resolve_credential_status_with_time(
        status,
        resolver,
        status_list_jwk,
        Some(now_unix_seconds),
        Some(expected_issuer),
    )
}

fn resolve_credential_status_with_time(
    status: &CredentialStatus,
    resolver: &impl HttpResolver,
    status_list_jwk: &PublicJwk,
    now_unix_seconds: Option<i64>,
    expected_issuer: Option<&str>,
) -> CoreResult<CredentialStatusResolution> {
    if status.type_ != BITSTRING_STATUS_LIST_ENTRY_TYPE {
        return Err(CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "credentialStatus type must be BitstringStatusListEntry",
        ));
    }
    let index = status
        .status_list_index
        .parse::<usize>()
        .map_err(|_| CoreError::new(CoreErrorCode::StatusCheckFailed, "invalid statusListIndex"))?;
    let expected_entry_id = format!("{}#{}", status.status_list_credential, index);
    if status.id != expected_entry_id {
        return Err(CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "credential status id does not match statusListCredential and statusListIndex",
        ));
    }

    let signed_list = resolver.resolve(&status.status_list_credential)?;
    let signed_list = std::str::from_utf8(&signed_list).map_err(|_| {
        CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "status-list resolver returned non-UTF-8 bytes",
        )
    })?;
    let (_, payload) = verify_bitstring_status_list_credential(signed_list, status_list_jwk)?;
    let expected_list_id = format!("{}#list", status.status_list_credential);
    if payload.credential_subject.id != expected_list_id {
        return Err(CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "status-list subject id does not match statusListCredential",
        ));
    }
    if let Some(expected_issuer) = expected_issuer
        && payload.issuer != expected_issuer
    {
        return Err(CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "status-list issuer does not match credential issuer",
        ));
    }
    if let Some(now_unix_seconds) = now_unix_seconds {
        ensure_status_list_fresh(&payload, now_unix_seconds)?;
    }
    if payload.credential_subject.status_purpose != status.status_purpose {
        return Err(CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "credential status purpose does not match status-list credential",
        ));
    }

    let revoked = bitstring_status_at(&payload.credential_subject.encoded_list, index)?;
    Ok(CredentialStatusResolution {
        status_list_credential: status.status_list_credential.clone(),
        status_list_index: index,
        status_purpose: status.status_purpose.clone(),
        revoked,
    })
}

/// Resolve status and reject credentials whose status bit is set.
pub fn verify_credential_status_active(
    status: &CredentialStatus,
    resolver: &impl HttpResolver,
    status_list_jwk: &PublicJwk,
) -> CoreResult<()> {
    let resolution = resolve_credential_status(status, resolver, status_list_jwk)?;
    if resolution.revoked {
        return Err(CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "credential status bit is set",
        ));
    }
    Ok(())
}

/// Resolve status at verifier time and reject stale lists or set status bits.
pub fn verify_credential_status_active_at(
    status: &CredentialStatus,
    resolver: &impl HttpResolver,
    status_list_jwk: &PublicJwk,
    now_unix_seconds: i64,
) -> CoreResult<()> {
    let resolution =
        resolve_credential_status_at(status, resolver, status_list_jwk, now_unix_seconds)?;
    if resolution.revoked {
        return Err(CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "credential status bit is set",
        ));
    }
    Ok(())
}

/// Verify attachment bytes against a disclosed signed SHA-256 hash.
///
/// UC4 uses this for the university photo attachment: the credential discloses
/// `photo_hash`, while the image bytes travel beside the presentation and are
/// never embedded in the credential.
pub fn verify_attachment(attachment_bytes: &[u8], expected_sha256_b64url: &str) -> CoreResult<()> {
    if sha256_b64url(attachment_bytes) != expected_sha256_b64url {
        return Err(CoreError::new(
            CoreErrorCode::AttachmentCheckFailed,
            "attachment SHA-256 hash does not match disclosed credential hash",
        ));
    }
    Ok(())
}

#[must_use]
pub fn b64_encode(input: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(input)
}

pub fn b64_decode(input: &str) -> CoreResult<Vec<u8>> {
    Base64UrlUnpadded::decode_vec(input).map_err(|_| {
        CoreError::new(
            CoreErrorCode::InvalidInput,
            "invalid unpadded base64url encoding",
        )
    })
}

/// Generate bounded URL-safe ceremony material from the operating-system
/// CSPRNG. Nonces, state, and opaque key handles use this single core seam.
pub fn random_urlsafe(byte_length: usize) -> CoreResult<String> {
    if !(16..=64).contains(&byte_length) {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "random URL-safe values must contain between 16 and 64 bytes",
        ));
    }
    let mut value = vec![0_u8; byte_length];
    getrandom::fill(&mut value).map_err(|error| {
        CoreError::new(
            CoreErrorCode::SigningFailed,
            format!("OS CSPRNG unavailable for URL-safe value: {error}"),
        )
    })?;
    Ok(b64_encode(&value))
}

/// Derive the two certificate-bound OID4VP client identifiers without
/// exposing certificate bytes or hashing to another runtime.
pub fn oid4vp_x509_client_ids(
    certificate_der_base64: &str,
    dns_name: &str,
) -> CoreResult<Oid4vpX509ClientIds> {
    validate_dns_name(dns_name)?;
    let certificate_der = Base64::decode_vec(certificate_der_base64).map_err(|_| {
        CoreError::new(
            CoreErrorCode::InvalidInput,
            "OID4VP x5c certificate must use padded standard base64",
        )
    })?;
    if certificate_der.is_empty() || certificate_der.len() > 65_536 {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "OID4VP x5c certificate has an invalid bounded size",
        ));
    }
    Ok(Oid4vpX509ClientIds {
        x509_san_dns: format!("x509_san_dns:{dns_name}"),
        x509_hash: format!("x509_hash:{}", sha256_b64url(&certificate_der)),
    })
}

/// Validate a HAIP issuer certificate path and return its usable AKI query values.
///
/// The trust anchor is supplied out of band and must not appear in `x5c`. Only
/// public certificate material enters this function.
pub fn oid4vp_haip_trusted_authority_key_identifiers(
    certificate_chain_der_base64: &[String],
    trust_anchors_der_base64: &[String],
    now_unix_seconds: i64,
) -> CoreResult<Vec<String>> {
    let validated = validate_oid4vp_x509_signing_chain(
        certificate_chain_der_base64,
        trust_anchors_der_base64,
        now_unix_seconds,
    )?;
    Ok(validated.authority_key_identifiers)
}

#[derive(Clone, Debug)]
struct ValidatedOid4vpX509Signer {
    public_jwk: PublicJwk,
    authority_key_identifiers: Vec<String>,
}

fn validate_oid4vp_x509_signing_chain(
    certificate_chain_der_base64: &[String],
    trust_anchors_der_base64: &[String],
    now_unix_seconds: i64,
) -> CoreResult<ValidatedOid4vpX509Signer> {
    if certificate_chain_der_base64.is_empty()
        || certificate_chain_der_base64.len() > OID4VP_MAX_X509_CERTIFICATES
        || trust_anchors_der_base64.is_empty()
        || trust_anchors_der_base64.len() > OID4VP_MAX_X509_CERTIFICATES
        || now_unix_seconds < 0
    {
        return Err(CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "OIDF HAIP certificate path inputs are invalid",
        ));
    }
    let chain = decode_oid4vp_certificates(certificate_chain_der_base64)?;
    let anchor_certificates = decode_oid4vp_certificates(trust_anchors_der_base64)?;
    if anchor_certificates.iter().any(|anchor| {
        chain
            .iter()
            .any(|certificate| anchor.as_ref() == certificate.as_ref())
    }) {
        return Err(CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "OIDF HAIP x5c certificate path must not include a trust anchor",
        ));
    }
    let anchors = anchor_certificates
        .iter()
        .map(anchor_from_trusted_cert)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            CoreError::new(
                CoreErrorCode::TrustCheckFailed,
                "OIDF HAIP trust anchor is not a valid X.509 certificate",
            )
        })?;
    let leaf = EndEntityCert::try_from(&chain[0]).map_err(|_| {
        CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "OIDF HAIP signing certificate is malformed",
        )
    })?;
    leaf.verify_for_usage(
        &[webpki::ring::ECDSA_P256_SHA256],
        &anchors,
        &chain[1..],
        UnixTime::since_unix_epoch(std::time::Duration::from_secs(
            u64::try_from(now_unix_seconds).map_err(|_| {
                CoreError::new(
                    CoreErrorCode::TrustCheckFailed,
                    "OIDF HAIP certificate validation time is invalid",
                )
            })?,
        )),
        WebPkiKeyUsage::client_auth(),
        None,
        None,
    )
    .map_err(|_| {
        CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "OIDF HAIP signing certificate path is not trusted or current",
        )
    })?;

    let (leaf_remainder, parsed_leaf) =
        parse_x509_certificate(chain[0].as_ref()).map_err(|_| {
            CoreError::new(
                CoreErrorCode::TrustCheckFailed,
                "OIDF HAIP signing certificate cannot be parsed",
            )
        })?;
    if !leaf_remainder.is_empty() {
        return Err(CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "OIDF HAIP signing certificate has trailing bytes",
        ));
    }
    let public_key = parsed_leaf.public_key();
    let is_p256 = public_key.algorithm.algorithm == OID_KEY_TYPE_EC_PUBLIC_KEY
        && public_key
            .algorithm
            .parameters
            .as_ref()
            .and_then(|parameters| parameters.as_oid().ok())
            .is_some_and(|curve| curve == OID_EC_P256);
    if !is_p256 {
        return Err(CoreError::new(
            CoreErrorCode::UnsupportedAlgorithm,
            "OIDF HAIP signing certificate must contain an ES256 P-256 key",
        ));
    }
    let point =
        PublicKey::from_sec1_bytes(public_key.subject_public_key.data.as_ref()).map_err(|_| {
            CoreError::new(
                CoreErrorCode::InvalidKey,
                "OIDF HAIP signing certificate public key is invalid",
            )
        })?;
    let encoded = point.to_sec1_point(false);
    let public_jwk = PublicJwk::p256(
        b64_encode(encoded.x().expect("uncompressed P-256 point has x")),
        b64_encode(encoded.y().expect("uncompressed P-256 point has y")),
        None,
    );
    let mut authority_key_identifiers = chain
        .iter()
        .filter_map(|certificate| {
            let (remainder, parsed) = parse_x509_certificate(certificate.as_ref()).ok()?;
            if !remainder.is_empty() {
                return None;
            }
            parsed.extensions().iter().find_map(|extension| {
                let ParsedExtension::AuthorityKeyIdentifier(authority) =
                    extension.parsed_extension()
                else {
                    return None;
                };
                authority
                    .key_identifier
                    .as_ref()
                    .map(|identifier| b64_encode(identifier.0))
            })
        })
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    authority_key_identifiers.sort();
    if authority_key_identifiers.is_empty() {
        return Err(CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "OIDF HAIP signing certificate chain has no Authority Key Identifier",
        ));
    }
    Ok(ValidatedOid4vpX509Signer {
        public_jwk,
        authority_key_identifiers,
    })
}

fn decode_oid4vp_certificates(values: &[String]) -> CoreResult<Vec<CertificateDer<'static>>> {
    values
        .iter()
        .map(|value| {
            let der = Base64::decode_vec(value).map_err(|_| {
                CoreError::new(
                    CoreErrorCode::TrustCheckFailed,
                    "OIDF HAIP x5c material is not padded base64 DER",
                )
            })?;
            if der.is_empty() || der.len() > 65_536 {
                return Err(CoreError::new(
                    CoreErrorCode::TrustCheckFailed,
                    "OIDF HAIP X.509 certificate exceeds its bounded size",
                ));
            }
            Ok(CertificateDer::from(der))
        })
        .collect()
}

fn validate_dns_name(dns_name: &str) -> CoreResult<()> {
    let valid = !dns_name.is_empty()
        && dns_name.len() <= 253
        && dns_name.is_ascii()
        && dns_name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|value| value.is_ascii_alphanumeric() || value == b'-')
        });
    if !valid {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "OID4VP x509_san_dns client identifier contains an invalid DNS name",
        ));
    }
    Ok(())
}

/// Generate a fresh P-256 response-encryption key for one OID4VP ceremony.
///
/// The secret is returned only to the Rust binding that owns the opaque key
/// store; language runtimes receive the public JWK.
pub fn generate_oid4vp_jwe_key(kid: String) -> CoreResult<(SecretKey, JwePublicJwk)> {
    if kid.is_empty() || kid.len() > 128 || !kid.is_ascii() {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "OID4VP JWE key identifier is invalid",
        ));
    }
    let secret = random_p256_secret()?;
    let public = JwePublicJwk::from_public_key(
        secret.public_key(),
        Some(kid),
        Some(OID4VP_JWE_ALG.to_owned()),
    );
    Ok((secret, public))
}

/// Encrypt a JSON value for the OID4VP `direct_post.jwt` test seam.
pub fn encrypt_oid4vp_jwe(plaintext: &Value, recipient_jwk: &JwePublicJwk) -> CoreResult<String> {
    validate_oid4vp_jwe_public_key(recipient_jwk)?;
    let ephemeral_secret = random_p256_secret()?;
    let mut iv = [0_u8; OID4VP_JWE_IV_BYTES];
    getrandom::fill(&mut iv).map_err(|error| {
        CoreError::new(
            CoreErrorCode::SigningFailed,
            format!("OS CSPRNG unavailable for OID4VP JWE: {error}"),
        )
    })?;
    encrypt_oid4vp_jwe_with_material(plaintext, recipient_jwk, &ephemeral_secret, &iv)
}

fn encrypt_oid4vp_jwe_with_material(
    plaintext: &Value,
    recipient_jwk: &JwePublicJwk,
    ephemeral_secret: &SecretKey,
    iv: &[u8; OID4VP_JWE_IV_BYTES],
) -> CoreResult<String> {
    let recipient_public = public_key_from_jwe_jwk(recipient_jwk)?;
    let shared_secret = diffie_hellman(
        ephemeral_secret.to_nonzero_scalar(),
        recipient_public.as_affine(),
    );
    let cek = ecdh_es_concat_kdf_bits(
        shared_secret.raw_secret_bytes().as_slice(),
        OID4VP_JWE_ENC,
        None,
        None,
        256,
    )?;
    let mut epk = JwePublicJwk::from_public_key(ephemeral_secret.public_key(), None, None);
    epk.kid = None;
    epk.alg = None;
    epk.key_use = None;
    let header = Oid4vpJweHeader {
        alg: OID4VP_JWE_ALG.to_owned(),
        enc: OID4VP_JWE_ENC.to_owned(),
        cty: Some("json".to_owned()),
        crit: None,
        kid: recipient_jwk.kid.clone(),
        epk: Some(epk),
        apu: None,
        apv: None,
    };
    let protected = encode_json_segment(&header)?;
    let plaintext = serde_json::to_vec(plaintext).map_err(json_error)?;
    if plaintext.len() as u64 > OID4VP_JWE_MAX_PLAINTEXT_BYTES {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "OID4VP JWE plaintext exceeds the bounded size",
        ));
    }
    let cipher = Aes256Gcm::new_from_slice(&cek).map_err(|_| {
        CoreError::new(
            CoreErrorCode::InvalidKey,
            "OID4VP JWE content-encryption key is invalid",
        )
    })?;
    let mut encrypted = cipher
        .encrypt(
            Nonce::from_slice(iv),
            Payload {
                msg: &plaintext,
                aad: protected.as_bytes(),
            },
        )
        .map_err(|_| {
            CoreError::new(CoreErrorCode::SigningFailed, "OID4VP JWE encryption failed")
        })?;
    if encrypted.len() < OID4VP_JWE_TAG_BYTES {
        return Err(CoreError::new(
            CoreErrorCode::SigningFailed,
            "OID4VP JWE omitted the authentication tag",
        ));
    }
    let tag = encrypted.split_off(encrypted.len() - OID4VP_JWE_TAG_BYTES);
    Ok(format!(
        "{protected}..{}.{}.{}",
        b64_encode(iv),
        b64_encode(&encrypted),
        b64_encode(&tag),
    ))
}

/// Decrypt and authenticate a bounded compact OID4VP response JWE.
pub fn decrypt_oid4vp_jwe(
    compact_jwe: &str,
    recipient_secret: &SecretKey,
    expected_kid: &str,
) -> CoreResult<Value> {
    if compact_jwe.len() > 2 * OID4VP_JWE_MAX_PLAINTEXT_BYTES as usize {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "OID4VP JWE exceeds the bounded input size",
        ));
    }
    let parts = compact_jwe.split('.').collect::<Vec<_>>();
    if parts.len() != 5 || parts[0].is_empty() || !parts[1].is_empty() {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "OID4VP JWE must use compact ECDH-ES serialization",
        ));
    }
    let header: Oid4vpJweHeader = decode_json_segment(parts[0])?;
    validate_oid4vp_jwe_header(&header, expected_kid)?;
    let ephemeral_public = public_key_from_jwe_jwk(header.epk.as_ref().ok_or_else(|| {
        CoreError::new(
            CoreErrorCode::InvalidKey,
            "OID4VP ECDH-ES JWE header is missing epk",
        )
    })?)?;
    let shared_secret = diffie_hellman(
        recipient_secret.to_nonzero_scalar(),
        ephemeral_public.as_affine(),
    );
    let cek = ecdh_es_concat_kdf_bits(
        shared_secret.raw_secret_bytes().as_slice(),
        &header.enc,
        header.apu.as_deref(),
        header.apv.as_deref(),
        if header.enc == OID4VP_JWE_ENC {
            256
        } else {
            128
        },
    )?;
    let iv = b64_decode(parts[2])?;
    let ciphertext = b64_decode(parts[3])?;
    let tag = b64_decode(parts[4])?;
    if iv.len() != OID4VP_JWE_IV_BYTES || tag.len() != OID4VP_JWE_TAG_BYTES {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "OID4VP JWE IV or authentication-tag length is invalid",
        ));
    }
    let mut authenticated_ciphertext = ciphertext;
    authenticated_ciphertext.extend_from_slice(&tag);
    let payload = Payload {
        msg: &authenticated_ciphertext,
        aad: parts[0].as_bytes(),
    };
    let plaintext = match header.enc.as_str() {
        OID4VP_JWE_ENC => Aes256Gcm::new_from_slice(&cek)
            .map_err(|_| invalid_oid4vp_cek())?
            .decrypt(Nonce::from_slice(&iv), payload)
            .map_err(|_| oid4vp_jwe_authentication_error())?,
        OID4VP_JWE_ENC_A128 => Aes128Gcm::new_from_slice(&cek)
            .map_err(|_| invalid_oid4vp_cek())?
            .decrypt(Nonce::from_slice(&iv), payload)
            .map_err(|_| oid4vp_jwe_authentication_error())?,
        _ => unreachable!("validated OID4VP JWE enc"),
    };
    if plaintext.len() as u64 > OID4VP_JWE_MAX_PLAINTEXT_BYTES {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "OID4VP JWE plaintext exceeds the bounded size",
        ));
    }
    let value: Value = serde_json::from_slice(&plaintext).map_err(json_error)?;
    if !value.is_object() {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "OID4VP JWE plaintext must be a JSON object",
        ));
    }
    Ok(value)
}

fn validate_oid4vp_jwe_public_key(jwk: &JwePublicJwk) -> CoreResult<()> {
    if jwk.alg.as_deref() != Some(OID4VP_JWE_ALG) || jwk.key_use.as_deref() != Some("enc") {
        return Err(CoreError::new(
            CoreErrorCode::InvalidKey,
            "OID4VP encryption JWK must select ECDH-ES for encryption",
        ));
    }
    public_key_from_jwe_jwk(jwk)?;
    Ok(())
}

fn validate_oid4vp_jwe_header(header: &Oid4vpJweHeader, expected_kid: &str) -> CoreResult<()> {
    if header.alg != OID4VP_JWE_ALG
        || ![OID4VP_JWE_ENC, OID4VP_JWE_ENC_A128].contains(&header.enc.as_str())
    {
        return Err(CoreError::new(
            CoreErrorCode::UnsupportedAlgorithm,
            "OID4VP JWE supports only ECDH-ES with A128GCM or A256GCM",
        ));
    }
    if header.cty.as_deref().is_some_and(|value| value != "json") || header.crit.is_some() {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "OID4VP JWE protected header is invalid",
        ));
    }
    if header.kid.as_deref() != Some(expected_kid) {
        return Err(CoreError::new(
            CoreErrorCode::InvalidKey,
            "OID4VP JWE kid does not select the ceremony key",
        ));
    }
    Ok(())
}

/// Encrypt an OID4VCI Credential Response as compact JWE using fresh in-core entropy.
///
/// The only supported profile is the standards-required asymmetric seam used by the
/// pinned suite: ECDH-ES with A256GCM and optional raw DEFLATE compression.
pub fn encrypt_oid4vci_credential_response(
    plaintext: &Value,
    parameters: &Oid4vciCredentialResponseEncryption,
) -> CoreResult<String> {
    let ephemeral_secret = random_p256_secret()?;
    let mut iv = [0_u8; OID4VCI_JWE_IV_BYTES];
    getrandom::fill(&mut iv).map_err(|error| {
        CoreError::new(
            CoreErrorCode::SigningFailed,
            format!("OS CSPRNG unavailable for credential-response encryption: {error}"),
        )
    })?;
    encrypt_oid4vci_credential_response_with_material(plaintext, parameters, &ephemeral_secret, &iv)
}

/// Deterministic OID4VCI JWE encryption seam for unit and independent-vector tests.
pub fn encrypt_oid4vci_credential_response_with_material(
    plaintext: &Value,
    parameters: &Oid4vciCredentialResponseEncryption,
    ephemeral_secret: &SecretKey,
    iv: &[u8; OID4VCI_JWE_IV_BYTES],
) -> CoreResult<String> {
    validate_oid4vci_credential_response_encryption(parameters)?;
    let recipient_public = public_key_from_jwe_jwk(&parameters.jwk)?;
    let shared_secret = diffie_hellman(
        ephemeral_secret.to_nonzero_scalar(),
        recipient_public.as_affine(),
    );
    let cek = ecdh_es_concat_kdf(
        shared_secret.raw_secret_bytes().as_slice(),
        OID4VCI_JWE_ENC,
        None,
        None,
    )?;
    let mut epk = JwePublicJwk::from_public_key(ephemeral_secret.public_key(), None, None);
    epk.key_use = None;
    let header = Oid4vciJweHeader {
        alg: OID4VCI_JWE_ALG.to_owned(),
        enc: OID4VCI_JWE_ENC.to_owned(),
        cty: "json".to_owned(),
        crit: None,
        kid: parameters.jwk.kid.clone(),
        epk: Some(epk),
        apu: None,
        apv: None,
        zip: parameters.zip.clone(),
    };
    let protected = encode_json_segment(&header)?;
    let mut payload = serde_json::to_vec(plaintext).map_err(json_error)?;
    if parameters.zip.as_deref() == Some(OID4VCI_JWE_ZIP) {
        payload = deflate_oid4vci_payload(&payload)?;
    }
    let cipher = Aes256Gcm::new_from_slice(&cek).map_err(|_| {
        CoreError::new(
            CoreErrorCode::InvalidKey,
            "OID4VCI JWE content-encryption key is invalid",
        )
    })?;
    let mut encrypted = cipher
        .encrypt(
            Nonce::from_slice(iv),
            Payload {
                msg: &payload,
                aad: protected.as_bytes(),
            },
        )
        .map_err(|_| {
            CoreError::new(
                CoreErrorCode::SigningFailed,
                "OID4VCI credential-response encryption failed",
            )
        })?;
    if encrypted.len() < OID4VCI_JWE_TAG_BYTES {
        return Err(CoreError::new(
            CoreErrorCode::SigningFailed,
            "OID4VCI credential-response encryption omitted the authentication tag",
        ));
    }
    let tag = encrypted.split_off(encrypted.len() - OID4VCI_JWE_TAG_BYTES);
    Ok(format!(
        "{protected}..{}.{}.{}",
        b64_encode(iv),
        b64_encode(&encrypted),
        b64_encode(&tag),
    ))
}

/// Encrypt a JSON OID4VCI request or response through the shared JWE implementation.
pub fn encrypt_oid4vci_jwe(
    plaintext: &Value,
    parameters: &Oid4vciCredentialResponseEncryption,
) -> CoreResult<String> {
    encrypt_oid4vci_credential_response(plaintext, parameters)
}

/// Deterministic alias used by wallet and independent-vector tests.
pub fn encrypt_oid4vci_jwe_with_material(
    plaintext: &Value,
    parameters: &Oid4vciCredentialResponseEncryption,
    ephemeral_secret: &SecretKey,
    iv: &[u8; OID4VCI_JWE_IV_BYTES],
) -> CoreResult<String> {
    encrypt_oid4vci_credential_response_with_material(plaintext, parameters, ephemeral_secret, iv)
}

/// Decrypt and authenticate an OID4VCI compact request/response JWE.
///
/// Callers keep `recipient_secret` behind an opaque Rust key handle. The result is
/// bounded to a JSON object/array of at most one MiB after optional decompression.
pub fn decrypt_oid4vci_jwe(
    compact_jwe: &str,
    recipient_secret: &SecretKey,
    expected_kid: Option<&str>,
) -> CoreResult<Value> {
    let parts = compact_jwe.split('.').collect::<Vec<_>>();
    if parts.len() != 5 || parts[0].is_empty() || !parts[1].is_empty() {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "OID4VCI request must use compact ECDH-ES JWE serialization",
        ));
    }
    let header: Oid4vciJweHeader = decode_json_segment(parts[0])?;
    validate_oid4vci_jwe_header(&header, expected_kid)?;
    let ephemeral_public = public_key_from_jwe_jwk(header.epk.as_ref().ok_or_else(|| {
        CoreError::new(
            CoreErrorCode::InvalidKey,
            "OID4VCI ECDH-ES JWE header is missing epk",
        )
    })?)?;
    let shared_secret = diffie_hellman(
        recipient_secret.to_nonzero_scalar(),
        ephemeral_public.as_affine(),
    );
    let cek = ecdh_es_concat_kdf(
        shared_secret.raw_secret_bytes().as_slice(),
        &header.enc,
        header.apu.as_deref(),
        header.apv.as_deref(),
    )?;
    let iv = b64_decode(parts[2])?;
    let ciphertext = b64_decode(parts[3])?;
    let tag = b64_decode(parts[4])?;
    if iv.len() != OID4VCI_JWE_IV_BYTES || tag.len() != OID4VCI_JWE_TAG_BYTES {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "OID4VCI JWE IV or authentication-tag length is invalid",
        ));
    }
    let mut authenticated_ciphertext = ciphertext;
    authenticated_ciphertext.extend_from_slice(&tag);
    let cipher = Aes256Gcm::new_from_slice(&cek).map_err(|_| {
        CoreError::new(
            CoreErrorCode::InvalidKey,
            "OID4VCI JWE content-encryption key is invalid",
        )
    })?;
    let mut plaintext = cipher
        .decrypt(
            Nonce::from_slice(&iv),
            Payload {
                msg: &authenticated_ciphertext,
                aad: parts[0].as_bytes(),
            },
        )
        .map_err(|_| {
            CoreError::new(
                CoreErrorCode::VerificationFailed,
                "OID4VCI JWE authentication failed",
            )
        })?;
    if header.zip.as_deref() == Some(OID4VCI_JWE_ZIP) {
        plaintext = inflate_oid4vci_payload(&plaintext)?;
    }
    if plaintext.len() as u64 > OID4VCI_JWE_MAX_PLAINTEXT_BYTES {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "OID4VCI JWE plaintext exceeds the bounded size",
        ));
    }
    let value: Value = serde_json::from_slice(&plaintext).map_err(json_error)?;
    if !value.is_object() && !value.is_array() {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "OID4VCI JWE plaintext must be a JSON object or array",
        ));
    }
    Ok(value)
}

/// Validate wallet-selected OID4VCI response-encryption parameters before issuance.
pub fn validate_oid4vci_credential_response_encryption(
    parameters: &Oid4vciCredentialResponseEncryption,
) -> CoreResult<()> {
    if parameters.enc != OID4VCI_JWE_ENC || parameters.jwk.alg.as_deref() != Some(OID4VCI_JWE_ALG) {
        return Err(CoreError::new(
            CoreErrorCode::UnsupportedAlgorithm,
            "OID4VCI encryption supports only ECDH-ES with A256GCM",
        ));
    }
    if parameters
        .jwk
        .key_use
        .as_deref()
        .is_some_and(|value| value != "enc")
    {
        return Err(CoreError::new(
            CoreErrorCode::InvalidKey,
            "OID4VCI encryption JWK use must be enc when present",
        ));
    }
    if parameters
        .zip
        .as_deref()
        .is_some_and(|value| value != OID4VCI_JWE_ZIP)
    {
        return Err(CoreError::new(
            CoreErrorCode::UnsupportedAlgorithm,
            "OID4VCI response compression supports only DEF",
        ));
    }
    public_key_from_jwe_jwk(&parameters.jwk)?;
    Ok(())
}

fn validate_oid4vci_jwe_header(
    header: &Oid4vciJweHeader,
    expected_kid: Option<&str>,
) -> CoreResult<()> {
    if header.alg != OID4VCI_JWE_ALG || header.enc != OID4VCI_JWE_ENC {
        return Err(CoreError::new(
            CoreErrorCode::UnsupportedAlgorithm,
            "OID4VCI JWE supports only ECDH-ES with A256GCM",
        ));
    }
    if header.cty != "json" {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "OID4VCI JWE cty must be json",
        ));
    }
    if header.crit.is_some() {
        return Err(CoreError::new(
            CoreErrorCode::UnsupportedAlgorithm,
            "OID4VCI JWE critical header extensions are unsupported",
        ));
    }
    if expected_kid.is_some_and(|expected| header.kid.as_deref() != Some(expected)) {
        return Err(CoreError::new(
            CoreErrorCode::InvalidKey,
            "OID4VCI JWE kid does not select the expected recipient key",
        ));
    }
    if header
        .zip
        .as_deref()
        .is_some_and(|value| value != OID4VCI_JWE_ZIP)
    {
        return Err(CoreError::new(
            CoreErrorCode::UnsupportedAlgorithm,
            "OID4VCI JWE compression supports only DEF",
        ));
    }
    Ok(())
}

fn public_key_from_jwe_jwk(jwk: &JwePublicJwk) -> CoreResult<PublicKey> {
    if jwk.kty != "EC" || jwk.crv != "P-256" {
        return Err(CoreError::new(
            CoreErrorCode::InvalidKey,
            "OID4VCI encryption JWK must be an EC P-256 public key",
        ));
    }
    let x = b64_decode(&jwk.x)?;
    let y = b64_decode(&jwk.y)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(CoreError::new(
            CoreErrorCode::InvalidKey,
            "OID4VCI encryption JWK coordinates must be 32 bytes each",
        ));
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    PublicKey::from_sec1_bytes(&sec1).map_err(|_| {
        CoreError::new(
            CoreErrorCode::InvalidKey,
            "OID4VCI encryption JWK is not a valid P-256 public point",
        )
    })
}

fn ecdh_es_concat_kdf(
    shared_secret: &[u8],
    algorithm: &str,
    apu: Option<&str>,
    apv: Option<&str>,
) -> CoreResult<[u8; 32]> {
    let derived = ecdh_es_concat_kdf_bits(shared_secret, algorithm, apu, apv, 256)?;
    derived.try_into().map_err(|_| {
        CoreError::new(
            CoreErrorCode::InvalidKey,
            "OID4VCI ECDH-ES KDF did not derive a 256-bit key",
        )
    })
}

fn ecdh_es_concat_kdf_bits(
    shared_secret: &[u8],
    algorithm: &str,
    apu: Option<&str>,
    apv: Option<&str>,
    key_data_bits: u32,
) -> CoreResult<Vec<u8>> {
    if key_data_bits == 0 || key_data_bits > 256 || key_data_bits % 8 != 0 {
        return Err(CoreError::new(
            CoreErrorCode::UnsupportedAlgorithm,
            "ECDH-ES single-round KDF supports byte-aligned keys up to 256 bits",
        ));
    }
    let mut input = Vec::new();
    input.extend_from_slice(&1_u32.to_be_bytes());
    input.extend_from_slice(shared_secret);
    append_length_prefixed(&mut input, algorithm.as_bytes())?;
    append_length_prefixed(&mut input, &decode_optional_party_info(apu)?)?;
    append_length_prefixed(&mut input, &decode_optional_party_info(apv)?)?;
    input.extend_from_slice(&key_data_bits.to_be_bytes());
    let digest = sha256(&input);
    Ok(digest[..(key_data_bits / 8) as usize].to_vec())
}

fn invalid_oid4vp_cek() -> CoreError {
    CoreError::new(
        CoreErrorCode::InvalidKey,
        "OID4VP JWE content-encryption key is invalid",
    )
}

fn oid4vp_jwe_authentication_error() -> CoreError {
    CoreError::new(
        CoreErrorCode::VerificationFailed,
        "OID4VP JWE authentication failed",
    )
}

fn decode_optional_party_info(value: Option<&str>) -> CoreResult<Vec<u8>> {
    value.map_or_else(|| Ok(Vec::new()), b64_decode)
}

fn append_length_prefixed(target: &mut Vec<u8>, value: &[u8]) -> CoreResult<()> {
    let len = u32::try_from(value.len()).map_err(|_| {
        CoreError::new(
            CoreErrorCode::InvalidInput,
            "OID4VCI JWE KDF input is too large",
        )
    })?;
    target.extend_from_slice(&len.to_be_bytes());
    target.extend_from_slice(value);
    Ok(())
}

fn deflate_oid4vci_payload(plaintext: &[u8]) -> CoreResult<Vec<u8>> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(plaintext).map_err(|error| {
        CoreError::new(
            CoreErrorCode::SigningFailed,
            format!("OID4VCI JWE compression failed: {error}"),
        )
    })?;
    encoder.finish().map_err(|error| {
        CoreError::new(
            CoreErrorCode::SigningFailed,
            format!("OID4VCI JWE compression finish failed: {error}"),
        )
    })
}

fn inflate_oid4vci_payload(compressed: &[u8]) -> CoreResult<Vec<u8>> {
    let decoder = DeflateDecoder::new(compressed);
    let mut bounded = decoder.take(OID4VCI_JWE_MAX_PLAINTEXT_BYTES + 1);
    let mut plaintext = Vec::new();
    bounded.read_to_end(&mut plaintext).map_err(|error| {
        CoreError::new(
            CoreErrorCode::VerificationFailed,
            format!("OID4VCI JWE decompression failed: {error}"),
        )
    })?;
    if plaintext.len() as u64 > OID4VCI_JWE_MAX_PLAINTEXT_BYTES {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "OID4VCI JWE decompressed plaintext exceeds the bounded size",
        ));
    }
    Ok(plaintext)
}

/// Generate a valid P-256 secret inside Rust for an opaque binding key store.
pub fn random_p256_secret() -> CoreResult<SecretKey> {
    for _ in 0..32 {
        let mut scalar = [0_u8; 32];
        getrandom::fill(&mut scalar).map_err(|error| {
            CoreError::new(
                CoreErrorCode::SigningFailed,
                format!("OS CSPRNG unavailable for ECDH-ES: {error}"),
            )
        })?;
        if let Ok(secret) = SecretKey::from_slice(&scalar) {
            return Ok(secret);
        }
    }
    Err(CoreError::new(
        CoreErrorCode::SigningFailed,
        "OS CSPRNG did not produce a valid P-256 ECDH scalar",
    ))
}

#[must_use]
pub fn sha256(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

#[must_use]
pub fn sha256_b64url(input: &[u8]) -> String {
    b64_encode(&sha256(input))
}

fn set_status_bit(bytes: &mut [u8], index: usize, value: bool) {
    let byte_index = index / 8;
    let bit_mask = 1_u8 << (7 - (index % 8));
    if value {
        bytes[byte_index] |= bit_mask;
    } else {
        bytes[byte_index] &= !bit_mask;
    }
}

fn get_status_bit(bytes: &[u8], index: usize) -> bool {
    let byte_index = index / 8;
    let bit_mask = 1_u8 << (7 - (index % 8));
    bytes[byte_index] & bit_mask != 0
}

fn gzip_base64url(bytes: &[u8]) -> CoreResult<String> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes).map_err(|error| {
        CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            format!("status list gzip encode failed: {error}"),
        )
    })?;
    let compressed = encoder.finish().map_err(|error| {
        CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            format!("status list gzip finish failed: {error}"),
        )
    })?;
    Ok(b64_encode(&compressed))
}

fn validate_status_list_payload(payload: &BitstringStatusListCredentialPayload) -> CoreResult<()> {
    if !payload
        .type_
        .iter()
        .any(|type_| type_ == BITSTRING_STATUS_LIST_CREDENTIAL_TYPE)
    {
        return Err(CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "status-list credential type is missing BitstringStatusListCredential",
        ));
    }
    if payload.credential_subject.type_ != BITSTRING_STATUS_LIST_TYPE {
        return Err(CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "status-list credentialSubject type must be BitstringStatusList",
        ));
    }
    if payload.credential_subject.status_purpose != "revocation"
        && payload.credential_subject.status_purpose != "suspension"
    {
        return Err(CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "status-list statusPurpose must be revocation or suspension",
        ));
    }
    Ok(())
}

fn ensure_status_list_fresh(
    payload: &BitstringStatusListCredentialPayload,
    now_unix_seconds: i64,
) -> CoreResult<()> {
    if let Some(valid_from) = &payload.valid_from {
        let valid_from = parse_rfc3339_z_seconds(valid_from)?;
        if now_unix_seconds < valid_from {
            return Err(CoreError::new(
                CoreErrorCode::StatusListStale,
                "status-list credential is not yet valid",
            ));
        }
    }
    if let Some(valid_until) = &payload.valid_until {
        let valid_until = parse_rfc3339_z_seconds(valid_until)?;
        if now_unix_seconds >= valid_until {
            return Err(CoreError::new(
                CoreErrorCode::StatusListStale,
                "status-list credential is expired",
            ));
        }
    }
    Ok(())
}

fn parse_rfc3339_z_seconds(value: &str) -> CoreResult<i64> {
    if value.len() != 20
        || &value[4..5] != "-"
        || &value[7..8] != "-"
        || &value[10..11] != "T"
        || &value[13..14] != ":"
        || &value[16..17] != ":"
        || &value[19..20] != "Z"
    {
        return Err(CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "status-list validFrom/validUntil must be UTC RFC3339 seconds",
        ));
    }
    let year = parse_datetime_part(&value[0..4], "year")? as i64;
    let month = parse_datetime_part(&value[5..7], "month")?;
    let day = parse_datetime_part(&value[8..10], "day")?;
    let hour = parse_datetime_part(&value[11..13], "hour")?;
    let minute = parse_datetime_part(&value[14..16], "minute")?;
    let second = parse_datetime_part(&value[17..19], "second")?;
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            "status-list validFrom/validUntil contains an invalid UTC date",
        ));
    }
    let days = days_from_civil(year, month, day);
    Ok(days * 86_400 + i64::from(hour) * 3_600 + i64::from(minute) * 60 + i64::from(second))
}

fn parse_datetime_part(value: &str, name: &str) -> CoreResult<u32> {
    value.parse::<u32>().map_err(|_| {
        CoreError::new(
            CoreErrorCode::StatusCheckFailed,
            format!("status-list validFrom/validUntil {name} is invalid"),
        )
    })
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day = i64::from(day);
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn validate_trust_list_payload(payload: &TrustListPayload) -> CoreResult<()> {
    if payload.id.trim().is_empty() {
        return Err(trust_check_error("trust-list id is required"));
    }
    if payload.issuer.trim().is_empty() {
        return Err(trust_check_error("trust-list issuer is required"));
    }
    did_web_to_https_url(&payload.issuer)
        .map_err(|_| trust_check_error("trust-list issuer must be a did:web identifier"))?;
    if payload.iat >= payload.exp {
        return Err(trust_check_error(
            "trust-list iat must be before trust-list exp",
        ));
    }
    if payload.entries.is_empty() {
        return Err(trust_check_error("trust-list entries cannot be empty"));
    }

    let mut seen_issuers = HashSet::new();
    for entry in &payload.entries {
        if entry.issuer_did.trim().is_empty() {
            return Err(trust_check_error("trust-list entry issuer_did is required"));
        }
        did_web_to_https_url(&entry.issuer_did).map_err(|_| {
            trust_check_error("trust-list entry issuer_did must be a did:web identifier")
        })?;
        if !seen_issuers.insert(entry.issuer_did.as_str()) {
            return Err(trust_check_error(format!(
                "trust-list has duplicate issuer entry: {}",
                entry.issuer_did
            )));
        }
        if entry.credential_types.is_empty()
            || entry
                .credential_types
                .iter()
                .any(|credential_type| credential_type.trim().is_empty())
        {
            return Err(trust_check_error(
                "trust-list entry credential_types cannot be empty",
            ));
        }

        let _ = pinned_trust_list_thumbprint(entry)?;
    }

    let mut seen_verifier_scopes = HashSet::new();
    for entry in &payload.verifiers {
        did_web_to_https_url(&entry.verifier_did).map_err(|_| {
            trust_check_error("verifier trust-list entry must contain a did:web verifier_did")
        })?;
        if entry.credential_type.trim().is_empty() || entry.profile_name.trim().is_empty() {
            return Err(trust_check_error(
                "verifier trust-list credential_type and profile_name are required",
            ));
        }
        if entry.claim_paths.is_empty()
            || entry.claim_paths.iter().any(|path| {
                path.is_empty() || path.iter().any(|component| component.trim().is_empty())
            })
        {
            return Err(trust_check_error(
                "verifier trust-list claim_paths cannot be empty",
            ));
        }
        let scope = (
            entry.verifier_did.as_str(),
            entry.credential_type.as_str(),
            entry.profile_name.as_str(),
        );
        if !seen_verifier_scopes.insert(scope) {
            return Err(trust_check_error(format!(
                "trust-list has duplicate verifier scope: {}/{}/{}",
                entry.verifier_did, entry.credential_type, entry.profile_name
            )));
        }
    }

    Ok(())
}

fn validate_oid4vp_request_payload(payload: &Value, now_unix_seconds: i64) -> CoreResult<()> {
    let client_id = oid4vp_required_string(payload, "client_id")?;
    let verifier_did =
        if let Some(did) = client_id.strip_prefix(OID4VP_DECENTRALIZED_IDENTIFIER_PREFIX) {
            did
        } else {
            return Err(CoreError::new(
                CoreErrorCode::VerificationFailed,
                "OID4VP client_id must use decentralized_identifier prefix",
            ));
        };
    if oid4vp_required_string(payload, "aud")? != OID4VP_WALLET_AUDIENCE {
        return Err(CoreError::new(
            CoreErrorCode::BindingCheckFailed,
            "OID4VP Request Object audience mismatch",
        ));
    }
    if oid4vp_required_string(payload, "response_type")? != "vp_token" {
        return Err(CoreError::new(
            CoreErrorCode::VerificationFailed,
            "OID4VP response_type must be vp_token",
        ));
    }
    if oid4vp_required_string(payload, "response_mode")? != "direct_post" {
        return Err(CoreError::new(
            CoreErrorCode::VerificationFailed,
            "OID4VP response_mode must be direct_post",
        ));
    }
    let response_uri = oid4vp_required_string(payload, "response_uri")?;
    if !(response_uri.starts_with("https://")
        || response_uri.starts_with("http://127.0.0.1:")
        || response_uri.starts_with("http://localhost:"))
    {
        return Err(CoreError::new(
            CoreErrorCode::VerificationFailed,
            "OID4VP response_uri must use HTTPS (or loopback HTTP for development)",
        ));
    }
    let did_document_url = did_web_to_https_url(verifier_did).map_err(|_| {
        CoreError::new(
            CoreErrorCode::VerificationFailed,
            "OID4VP decentralized_identifier client_id must contain a did:web DID",
        )
    })?;
    let verifier_origin = https_origin(&did_document_url)?;
    if !is_loopback_http_uri(response_uri) && !uri_has_origin(response_uri, verifier_origin) {
        return Err(CoreError::new(
            CoreErrorCode::BindingCheckFailed,
            "OID4VP response_uri origin is not controlled by the verifier DID",
        ));
    }
    if payload.get("redirect_uri").is_some() {
        return Err(CoreError::new(
            CoreErrorCode::VerificationFailed,
            "OID4VP direct_post Request Object must not contain redirect_uri",
        ));
    }
    let nonce = oid4vp_required_string(payload, "nonce")?;
    if nonce.len() < 16
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(CoreError::new(
            CoreErrorCode::FreshnessCheckFailed,
            "OID4VP nonce must be fresh URL-safe random data",
        ));
    }
    let state = oid4vp_required_string(payload, "state")?;
    if state.len() < 16
        || !state
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(CoreError::new(
            CoreErrorCode::FreshnessCheckFailed,
            "OID4VP state must be fresh URL-safe random data",
        ));
    }
    let iat = oid4vp_required_i64(payload, "iat")?;
    let exp = oid4vp_required_i64(payload, "exp")?;
    if iat >= exp || exp - iat > 300 || iat > now_unix_seconds + 5 || now_unix_seconds >= exp {
        return Err(CoreError::new(
            CoreErrorCode::FreshnessCheckFailed,
            "OID4VP Request Object is outside its validity window",
        ));
    }
    let credentials = payload
        .get("dcql_query")
        .and_then(Value::as_object)
        .and_then(|dcql| dcql.get("credentials"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::VerificationFailed,
                "OID4VP Request Object must contain a DCQL credentials query",
            )
        })?;
    if credentials.is_empty() {
        return Err(CoreError::new(
            CoreErrorCode::VerificationFailed,
            "OID4VP DCQL credentials query cannot be empty",
        ));
    }
    for credential in credentials {
        if !matches!(
            credential.get("format").and_then(Value::as_str),
            Some("vc+sd-jwt" | "dc+sd-jwt")
        ) {
            return Err(CoreError::new(
                CoreErrorCode::VerificationFailed,
                "OID4VP DCQL credential format must be vc+sd-jwt or dc+sd-jwt",
            ));
        }
    }
    Ok(())
}

fn validate_oid4vp_interop_metadata(payload: &Value) -> CoreResult<()> {
    let format = payload
        .get("client_metadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("vp_formats_supported"))
        .and_then(Value::as_object)
        .and_then(|formats| formats.get(DC_SD_JWT_TYP))
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::VerificationFailed,
                "OIDF wallet client metadata does not support dc+sd-jwt",
            )
        })?;
    for name in ["sd-jwt_alg_values", "kb-jwt_alg_values"] {
        let algorithms = format.get(name).and_then(Value::as_array).ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::VerificationFailed,
                "OIDF wallet client metadata algorithm set is invalid",
            )
        })?;
        if !algorithms
            .iter()
            .any(|value| value.as_str() == Some("ES256"))
        {
            return Err(CoreError::new(
                CoreErrorCode::UnsupportedAlgorithm,
                "OIDF wallet client metadata must support ES256",
            ));
        }
    }
    Ok(())
}

fn validate_oid4vp_interop_dcql(
    payload: &Value,
    policy: &Oid4vpWalletRequestPolicy,
) -> CoreResult<(Vec<Oid4vpWalletCredentialSelection>, bool)> {
    let dcql = payload
        .get("dcql_query")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::VerificationFailed,
                "OIDF wallet request is missing a DCQL query",
            )
        })?;
    let credentials = dcql
        .get("credentials")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::VerificationFailed,
                "OIDF wallet DCQL credentials must be an array",
            )
        })?;
    if credentials.is_empty() || credentials.len() > 16 {
        return Err(CoreError::new(
            CoreErrorCode::VerificationFailed,
            "OIDF wallet DCQL credential count is unsupported",
        ));
    }
    let mut credential_ids = HashSet::new();
    let mut credential_order = Vec::with_capacity(credentials.len());
    for credential in credentials {
        let credential = credential.as_object().ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::VerificationFailed,
                "OIDF wallet DCQL credential must be an object",
            )
        })?;
        if let Some(meta) = credential.get("meta") {
            let meta = meta.as_object().ok_or_else(|| {
                CoreError::new(
                    CoreErrorCode::VerificationFailed,
                    "OIDF wallet DCQL credential metadata must be an object",
                )
            })?;
            if let Some(vct_values) = meta.get("vct_values") {
                let vct_values = vct_values
                    .as_array()
                    .filter(|values| !values.is_empty() && values.len() <= 16)
                    .ok_or_else(|| {
                        CoreError::new(
                            CoreErrorCode::VerificationFailed,
                            "OIDF wallet DCQL credential metadata is invalid",
                        )
                    })?;
                if vct_values.iter().any(|value| {
                    value
                        .as_str()
                        .is_none_or(|value| value.is_empty() || value.len() > 256)
                }) {
                    return Err(CoreError::new(
                        CoreErrorCode::VerificationFailed,
                        "OIDF wallet DCQL credential metadata is invalid",
                    ));
                }
            }
        }
        if let Some(claims) = credential.get("claims") {
            let claims = claims.as_array().ok_or_else(|| {
                CoreError::new(
                    CoreErrorCode::VerificationFailed,
                    "OIDF wallet DCQL claims must be an array",
                )
            })?;
            for claim in claims {
                claim.as_object().ok_or_else(|| {
                    CoreError::new(
                        CoreErrorCode::VerificationFailed,
                        "OIDF wallet DCQL claim must be an object",
                    )
                })?;
            }
        }
        for name in ["multiple", "require_cryptographic_holder_binding"] {
            if credential
                .get(name)
                .is_some_and(|value| !value.is_boolean())
            {
                return Err(CoreError::new(
                    CoreErrorCode::VerificationFailed,
                    "OIDF wallet DCQL credential boolean is invalid",
                ));
            }
        }
        let credential_id = credential
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| valid_dcql_id(value))
            .ok_or_else(|| {
                CoreError::new(
                    CoreErrorCode::VerificationFailed,
                    "OIDF wallet DCQL credential id is invalid",
                )
            })?;
        if !credential_ids.insert(credential_id.to_owned()) {
            return Err(CoreError::new(
                CoreErrorCode::VerificationFailed,
                "OIDF wallet DCQL credential ids must be unique",
            ));
        }
        credential_order.push(credential_id.to_owned());
    }
    let matching_credentials = credentials
        .iter()
        .enumerate()
        .filter(|(_, credential)| {
            credential
                .as_object()
                .is_some_and(oid4vp_wallet_holds_credential_type)
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let mut satisfiable_selections = Vec::with_capacity(matching_credentials.len());
    for held_credential_index in matching_credentials {
        let credential = credentials[held_credential_index]
            .as_object()
            .ok_or_else(|| {
                CoreError::new(
                    CoreErrorCode::VerificationFailed,
                    "OIDF wallet DCQL credential must be an object",
                )
            })?;
        let credential_id = credential
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| valid_dcql_id(value))
            .ok_or_else(|| {
                CoreError::new(
                    CoreErrorCode::VerificationFailed,
                    "OIDF wallet DCQL credential id is invalid",
                )
            })?;
        let authority_satisfied = validate_oid4vp_trusted_authorities(
            credential.get("trusted_authorities"),
            &policy.trusted_authority_key_identifiers,
        )?;
        let mut selected_claims = Vec::new();
        let mut claims_satisfied = true;
        if let Some(requested) = credential.get("claims") {
            let requested = requested
                .as_array()
                .filter(|claims| {
                    !claims.is_empty()
                        && claims.len() <= policy.available_claims.len().saturating_add(8)
                })
                .ok_or_else(|| {
                    CoreError::new(
                        CoreErrorCode::VerificationFailed,
                        "OIDF wallet DCQL claims must be a bounded non-empty array",
                    )
                })?;
            let mut candidates = Vec::with_capacity(requested.len());
            let mut seen_paths = HashSet::new();
            let mut seen_ids = HashSet::new();
            for claim in requested {
                let object = claim.as_object().ok_or_else(|| {
                    CoreError::new(
                        CoreErrorCode::VerificationFailed,
                        "OIDF wallet DCQL claim must be an object",
                    )
                })?;
                let path = claim
                    .get("path")
                    .and_then(Value::as_array)
                    .filter(|path| path.len() == 1)
                    .and_then(|path| path[0].as_str())
                    .ok_or_else(|| {
                        CoreError::new(
                            CoreErrorCode::VerificationFailed,
                            "OIDF wallet DCQL claim path is invalid",
                        )
                    })?;
                if !["given_name", "family_name"].contains(&path) || !seen_paths.insert(path) {
                    return Err(CoreError::new(
                        CoreErrorCode::MissingDisclosure,
                        "OIDF wallet DCQL request is over-broad or duplicated",
                    ));
                }
                let id = object
                    .get("id")
                    .map(|value| {
                        value
                            .as_str()
                            .filter(|value| valid_dcql_id(value))
                            .ok_or_else(|| {
                                CoreError::new(
                                    CoreErrorCode::VerificationFailed,
                                    "OIDF wallet DCQL claim id is invalid",
                                )
                            })
                    })
                    .transpose()?;
                if id.is_some_and(|value| !seen_ids.insert(value)) {
                    return Err(CoreError::new(
                        CoreErrorCode::VerificationFailed,
                        "OIDF wallet DCQL claim ids must be unique",
                    ));
                }
                let available_value = policy.available_claims.get(path);
                let available = match object.get("values") {
                    None => available_value.is_some(),
                    Some(values) => {
                        let values = values
                            .as_array()
                            .filter(|values| !values.is_empty() && values.len() <= 16)
                            .ok_or_else(|| {
                                CoreError::new(
                                    CoreErrorCode::VerificationFailed,
                                    "OIDF wallet DCQL claim values are invalid",
                                )
                            })?;
                        if values.iter().any(|value| {
                            !value.is_string()
                                && !value.is_boolean()
                                && !value.as_i64().is_some()
                                && !value.as_u64().is_some()
                        }) {
                            return Err(CoreError::new(
                                CoreErrorCode::VerificationFailed,
                                "OIDF wallet DCQL claim values must be scalar",
                            ));
                        }
                        available_value
                            .is_some_and(|actual| values.iter().any(|value| value == actual))
                    }
                };
                candidates.push((id.map(str::to_owned), path.to_owned(), available));
            }

            if let Some(claim_sets) = credential.get("claim_sets") {
                if candidates.iter().any(|(id, _, _)| id.is_none()) {
                    return Err(CoreError::new(
                        CoreErrorCode::VerificationFailed,
                        "OIDF wallet DCQL claim_sets require claim ids",
                    ));
                }
                let claim_sets = claim_sets
                    .as_array()
                    .filter(|sets| !sets.is_empty() && sets.len() <= 16)
                    .ok_or_else(|| {
                        CoreError::new(
                            CoreErrorCode::VerificationFailed,
                            "OIDF wallet DCQL claim_sets are invalid",
                        )
                    })?;
                let mut first_satisfiable = None;
                for option in claim_sets {
                    let option = option
                        .as_array()
                        .filter(|ids| !ids.is_empty() && ids.len() <= candidates.len())
                        .ok_or_else(|| {
                            CoreError::new(
                                CoreErrorCode::VerificationFailed,
                                "OIDF wallet DCQL claim-set option is invalid",
                            )
                        })?;
                    let mut option_paths = Vec::with_capacity(option.len());
                    let mut option_ids = HashSet::new();
                    let mut satisfiable = true;
                    for id in option {
                        let id = id
                            .as_str()
                            .filter(|value| valid_dcql_id(value))
                            .ok_or_else(|| {
                                CoreError::new(
                                    CoreErrorCode::VerificationFailed,
                                    "OIDF wallet DCQL claim-set reference is invalid",
                                )
                            })?;
                        if !option_ids.insert(id) {
                            return Err(CoreError::new(
                                CoreErrorCode::VerificationFailed,
                                "OIDF wallet DCQL claim-set contains a duplicate reference",
                            ));
                        }
                        let (_, path, available) = candidates
                            .iter()
                            .find(|(candidate_id, _, _)| candidate_id.as_deref() == Some(id))
                            .ok_or_else(|| {
                                CoreError::new(
                                    CoreErrorCode::VerificationFailed,
                                    "OIDF wallet DCQL claim-set references an unknown claim",
                                )
                            })?;
                        option_paths.push(path.clone());
                        satisfiable &= *available;
                    }
                    if satisfiable && first_satisfiable.is_none() {
                        first_satisfiable = Some(option_paths);
                    }
                }
                if let Some(paths) = first_satisfiable {
                    selected_claims = paths;
                } else {
                    claims_satisfied = false;
                }
            } else if candidates.iter().all(|(_, _, available)| *available) {
                selected_claims = candidates.into_iter().map(|(_, path, _)| path).collect();
            } else {
                claims_satisfied = false;
            }
        } else if credential.get("claim_sets").is_some() {
            return Err(CoreError::new(
                CoreErrorCode::VerificationFailed,
                "OIDF wallet DCQL claim_sets cannot be used without claims",
            ));
        }

        if authority_satisfied && claims_satisfied {
            satisfiable_selections.push(Oid4vpWalletCredentialSelection {
                credential_id: credential_id.to_owned(),
                requested_claims: selected_claims,
            });
        }
    }

    let satisfiable_credential_ids = satisfiable_selections
        .iter()
        .map(|selection| selection.credential_id.clone())
        .collect::<HashSet<_>>();
    let Some(selected_credential_ids) = select_oid4vp_credential_ids(
        dcql.get("credential_sets"),
        &credential_order,
        &credential_ids,
        &satisfiable_credential_ids,
    )?
    else {
        return Ok((Vec::new(), false));
    };
    satisfiable_selections
        .retain(|selection| selected_credential_ids.contains(&selection.credential_id));
    let satisfied = !satisfiable_selections.is_empty();
    Ok((satisfiable_selections, satisfied))
}

fn valid_dcql_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || value == b'_' || value == b'-')
}

fn oid4vp_wallet_holds_credential_type(credential: &Map<String, Value>) -> bool {
    credential.get("format").and_then(Value::as_str) == Some(DC_SD_JWT_TYP)
        && credential
            .get("meta")
            .and_then(Value::as_object)
            .and_then(|meta| meta.get("vct_values"))
            .and_then(Value::as_array)
            .is_some_and(|values| {
                values
                    .iter()
                    .any(|value| value.as_str() == Some("urn:eudi:pid:1"))
            })
}

fn validate_oid4vp_trusted_authorities(
    value: Option<&Value>,
    trusted_authority_key_identifiers: &[String],
) -> CoreResult<bool> {
    let Some(value) = value else {
        return Ok(true);
    };
    let authorities = value
        .as_array()
        .filter(|authorities| !authorities.is_empty() && authorities.len() <= 16)
        .ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::VerificationFailed,
                "OIDF wallet trusted_authorities must be a bounded non-empty array",
            )
        })?;
    let mut matched = false;
    for authority in authorities {
        let authority = authority.as_object().ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::VerificationFailed,
                "OIDF wallet trusted authority must be an object",
            )
        })?;
        let kind = authority
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CoreError::new(
                    CoreErrorCode::VerificationFailed,
                    "OIDF wallet trusted authority type is invalid",
                )
            })?;
        let values = authority
            .get("values")
            .and_then(Value::as_array)
            .filter(|values| !values.is_empty() && values.len() <= 32)
            .ok_or_else(|| {
                CoreError::new(
                    CoreErrorCode::VerificationFailed,
                    "OIDF wallet trusted authority values are invalid",
                )
            })?;
        if values.iter().any(|value| {
            value
                .as_str()
                .is_none_or(|value| value.is_empty() || value.len() > 256)
        }) {
            return Err(CoreError::new(
                CoreErrorCode::VerificationFailed,
                "OIDF wallet trusted authority value is invalid",
            ));
        }
        if kind == "aki"
            && values.iter().any(|value| {
                value.as_str().is_some_and(|value| {
                    trusted_authority_key_identifiers
                        .iter()
                        .any(|trusted| trusted == value)
                })
            })
        {
            matched = true;
        }
    }
    Ok(matched)
}

fn select_oid4vp_credential_ids(
    value: Option<&Value>,
    credential_order: &[String],
    credential_ids: &HashSet<String>,
    satisfiable_credential_ids: &HashSet<String>,
) -> CoreResult<Option<HashSet<String>>> {
    let Some(value) = value else {
        return Ok(credential_order
            .iter()
            .all(|credential_id| satisfiable_credential_ids.contains(credential_id))
            .then(|| credential_order.iter().cloned().collect()));
    };
    let sets = value
        .as_array()
        .filter(|sets| !sets.is_empty() && sets.len() <= 16)
        .ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::VerificationFailed,
                "OIDF wallet DCQL credential_sets must be a bounded non-empty array",
            )
        })?;
    let mut required_options = Vec::new();
    let mut optional_options = Vec::new();
    for set in sets {
        let set = set.as_object().ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::VerificationFailed,
                "OIDF wallet DCQL credential set must be an object",
            )
        })?;
        let required = match set.get("required") {
            None => true,
            Some(value) => value.as_bool().ok_or_else(|| {
                CoreError::new(
                    CoreErrorCode::VerificationFailed,
                    "OIDF wallet DCQL credential-set requirement is invalid",
                )
            })?,
        };
        let options = set
            .get("options")
            .and_then(Value::as_array)
            .filter(|options| !options.is_empty() && options.len() <= 16)
            .ok_or_else(|| {
                CoreError::new(
                    CoreErrorCode::VerificationFailed,
                    "OIDF wallet DCQL credential-set options are invalid",
                )
            })?;
        let mut satisfiable_options = Vec::new();
        for option in options {
            let option = option
                .as_array()
                .filter(|ids| !ids.is_empty() && ids.len() <= credential_ids.len())
                .ok_or_else(|| {
                    CoreError::new(
                        CoreErrorCode::VerificationFailed,
                        "OIDF wallet DCQL credential-set option is invalid",
                    )
                })?;
            let mut option_ids = HashSet::new();
            let mut option_satisfied = true;
            let mut option_mask = 0_u32;
            for credential_id in option {
                let credential_id = credential_id
                    .as_str()
                    .filter(|value| valid_dcql_id(value))
                    .ok_or_else(|| {
                        CoreError::new(
                            CoreErrorCode::VerificationFailed,
                            "OIDF wallet DCQL credential-set reference is invalid",
                        )
                    })?;
                if !credential_ids.contains(credential_id) || !option_ids.insert(credential_id) {
                    return Err(CoreError::new(
                        CoreErrorCode::VerificationFailed,
                        "OIDF wallet DCQL credential set contains an unknown or duplicate reference",
                    ));
                }
                option_satisfied &= satisfiable_credential_ids.contains(credential_id);
                let credential_index = credential_order
                    .iter()
                    .position(|candidate| candidate == credential_id)
                    .ok_or_else(|| {
                        CoreError::new(
                            CoreErrorCode::VerificationFailed,
                            "OIDF wallet DCQL credential set contains an unknown reference",
                        )
                    })?;
                option_mask |= 1_u32 << credential_index;
            }
            if option_satisfied {
                satisfiable_options.push(option_mask);
            }
        }
        if required {
            if satisfiable_options.is_empty() {
                return Ok(None);
            }
            required_options.push(satisfiable_options);
        } else {
            optional_options.extend(satisfiable_options);
        }
    }

    let rank_mask = |mask: &u32| {
        (
            mask.count_ones(),
            (0..credential_order.len())
                .filter(|index| mask & (1_u32 << index) != 0)
                .collect::<Vec<_>>(),
        )
    };
    let selected_mask = if required_options.is_empty() {
        optional_options.into_iter().min_by_key(rank_mask)
    } else {
        let mut compatible_unions = vec![0_u32];
        for options in required_options {
            compatible_unions = compatible_unions
                .iter()
                .flat_map(|selected| options.iter().map(move |option| selected | option))
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
        }
        compatible_unions.into_iter().min_by_key(rank_mask)
    };
    Ok(selected_mask.map(|mask| {
        credential_order
            .iter()
            .enumerate()
            .filter(|(index, _)| mask & (1_u32 << index) != 0)
            .map(|(_, credential_id)| credential_id.clone())
            .collect()
    }))
}

fn select_oid4vp_encryption_key(payload: &Value) -> CoreResult<JwePublicJwk> {
    let metadata = payload
        .get("client_metadata")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CoreError::new(CoreErrorCode::InvalidKey, "OIDF HAIP metadata is missing")
        })?;
    let enc = metadata
        .get("encrypted_response_enc_values_supported")
        .and_then(Value::as_array)
        .filter(|values| {
            values
                .iter()
                .any(|value| value.as_str() == Some(OID4VP_JWE_ENC))
        })
        .ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::UnsupportedAlgorithm,
                "OIDF HAIP metadata must support A256GCM",
            )
        })?;
    let _ = enc;
    let keys = metadata
        .get("jwks")
        .and_then(Value::as_object)
        .and_then(|jwks| jwks.get("keys"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::InvalidKey,
                "OIDF HAIP encryption keys are missing",
            )
        })?;
    let mut usable = keys.iter().filter_map(|value| {
        let object = value.as_object()?;
        if object.get("d").is_some()
            || object.get("kty").and_then(Value::as_str) != Some("EC")
            || object.get("crv").and_then(Value::as_str) != Some("P-256")
            || object.get("alg").and_then(Value::as_str) != Some(OID4VP_JWE_ALG)
            || object
                .get("use")
                .and_then(Value::as_str)
                .is_some_and(|value| value != "enc")
        {
            return None;
        }
        serde_json::from_value::<JwePublicJwk>(value.clone()).ok()
    });
    let key = usable.next().ok_or_else(|| {
        CoreError::new(
            CoreErrorCode::InvalidKey,
            "OIDF HAIP metadata has no usable ECDH-ES key",
        )
    })?;
    if usable.next().is_some() {
        return Err(CoreError::new(
            CoreErrorCode::InvalidKey,
            "OIDF HAIP metadata has ambiguous usable encryption keys",
        ));
    }
    validate_oid4vp_wallet_response_public_key(&key)?;
    Ok(key)
}

fn validate_oid4vp_wallet_response_public_key(jwk: &JwePublicJwk) -> CoreResult<()> {
    if jwk.alg.as_deref() != Some(OID4VP_JWE_ALG)
        || jwk.key_use.as_deref().is_some_and(|value| value != "enc")
    {
        return Err(CoreError::new(
            CoreErrorCode::InvalidKey,
            "OID4VP encryption JWK must select ECDH-ES",
        ));
    }
    public_key_from_jwe_jwk(jwk)?;
    Ok(())
}

fn decode_x5c_leaf(value: &str) -> CoreResult<Vec<u8>> {
    Base64::decode_vec(value).map_err(|_| {
        CoreError::new(
            CoreErrorCode::TrustCheckFailed,
            "OIDF HAIP x5c leaf is not padded base64 DER",
        )
    })
}

fn oid4vp_audience_is_self_issued(value: Option<&Value>) -> bool {
    match value {
        Some(Value::String(value)) => value == OID4VP_WALLET_AUDIENCE,
        Some(Value::Array(values)) => {
            values.len() == 1 && values[0].as_str() == Some(OID4VP_WALLET_AUDIENCE)
        }
        _ => false,
    }
}

fn oidf_suite_response_uri_matches_request(request_uri: &str, response_uri: &str) -> bool {
    let Some((base, request_token)) = request_uri.rsplit_once("/requesturi/") else {
        return false;
    };
    request_token.len() == 64
        && request_token
            .bytes()
            .all(|value| value.is_ascii_alphanumeric())
        && response_uri == format!("{base}/responseuri")
}

fn is_strict_https_uri(value: &str) -> bool {
    value.starts_with("https://")
        && !value.contains('@')
        && !value.contains('#')
        && uri_origin(value).is_some()
}

fn uri_origin(value: &str) -> Option<String> {
    let rest = value.strip_prefix("https://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty() || authority.contains('@') || authority.contains(char::is_whitespace) {
        return None;
    }
    Some(format!("https://{authority}"))
}

fn https_origin(uri: &str) -> CoreResult<&str> {
    let without_scheme = uri.strip_prefix("https://").ok_or_else(|| {
        CoreError::new(CoreErrorCode::VerificationFailed, "expected an HTTPS URI")
    })?;
    let authority_len = without_scheme
        .find(['/', '?', '#'])
        .unwrap_or(without_scheme.len());
    Ok(&uri[.."https://".len() + authority_len])
}

fn is_loopback_http_uri(uri: &str) -> bool {
    uri.starts_with("http://127.0.0.1:") || uri.starts_with("http://localhost:")
}

fn uri_has_origin(uri: &str, origin: &str) -> bool {
    uri == origin
        || uri
            .strip_prefix(origin)
            .is_some_and(|suffix| suffix.starts_with('/') || suffix.starts_with('?'))
}

fn oid4vp_required_string<'a>(payload: &'a Value, name: &str) -> CoreResult<&'a str> {
    payload.get(name).and_then(Value::as_str).ok_or_else(|| {
        CoreError::new(
            CoreErrorCode::VerificationFailed,
            format!("OID4VP Request Object {name} must be a string"),
        )
    })
}

fn oid4vp_required_i64(payload: &Value, name: &str) -> CoreResult<i64> {
    payload.get(name).and_then(Value::as_i64).ok_or_else(|| {
        CoreError::new(
            CoreErrorCode::VerificationFailed,
            format!("OID4VP Request Object {name} must be an integer"),
        )
    })
}

fn pinned_trust_list_thumbprint(entry: &TrustListEntry) -> CoreResult<String> {
    let jwk_thumbprint = entry
        .public_jwk
        .as_ref()
        .map(public_jwk_sha256_thumbprint)
        .transpose()
        .map_err(|_| trust_check_error("trust-list entry public_jwk is invalid"))?;

    match (
        jwk_thumbprint,
        entry.public_jwk_sha256_thumbprint.as_deref(),
    ) {
        (Some(calculated), Some(pinned)) if calculated != pinned => Err(trust_check_error(
            "trust-list entry public_jwk does not match thumbprint pin",
        )),
        (Some(calculated), _) => Ok(calculated),
        (None, Some(pinned)) if !pinned.trim().is_empty() => Ok(pinned.to_owned()),
        _ => Err(trust_check_error(
            "trust-list entry is missing issuer key pin",
        )),
    }
}

fn trust_check_error(message: impl Into<String>) -> CoreError {
    CoreError::new(CoreErrorCode::TrustCheckFailed, message)
}

fn encode_disclosure(salt: &str, claim_name: &str, claim_value: &Value) -> CoreResult<String> {
    let disclosure = json!([salt, claim_name, claim_value]);
    serde_json::to_vec(&disclosure)
        .map(|json| b64_encode(&json))
        .map_err(json_error)
}

fn decode_disclosure(encoded: &str) -> CoreResult<DecodedDisclosure> {
    let disclosure_json = b64_decode(encoded)?;
    let disclosure: Vec<Value> = serde_json::from_slice(&disclosure_json).map_err(json_error)?;
    if disclosure.len() != 2 && disclosure.len() != 3 {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "disclosure must contain [salt, value] or [salt, name, value]",
        ));
    }
    if disclosure[0].as_str().is_none() {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "disclosure salt must be a string",
        ));
    }
    let array_element = disclosure.len() == 2;
    let (claim_name, claim_value) = if array_element {
        (String::new(), disclosure[1].clone())
    } else {
        let claim_name = disclosure[1].as_str().ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::InvalidInput,
                "object claim disclosure name must be a string",
            )
        })?;
        (claim_name.to_owned(), disclosure[2].clone())
    };

    Ok(DecodedDisclosure {
        claim_name,
        claim_value,
        array_element,
        encoded: encoded.to_owned(),
        digest: sha256_b64url(encoded.as_bytes()),
    })
}

fn split_sd_jwt(serialized: &str) -> CoreResult<(&str, Vec<&str>, Option<&str>)> {
    let parts: Vec<&str> = serialized.split('~').collect();
    if parts.len() < 2 {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "SD-JWT must contain tilde-separated components",
        ));
    }
    let issuer_jwt = parts[0];
    if issuer_jwt.is_empty() {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "SD-JWT issuer JWT is empty",
        ));
    }

    match parts.last().copied() {
        Some("") => Ok((issuer_jwt, parts[1..parts.len() - 1].to_vec(), None)),
        Some(kb_jwt) => Ok((issuer_jwt, parts[1..parts.len() - 1].to_vec(), Some(kb_jwt))),
        None => unreachable!("parts has at least two entries"),
    }
}

fn decode_jws_payload_unverified(compact_jws: &str) -> CoreResult<Value> {
    let parts: Vec<&str> = compact_jws.split('.').collect();
    if parts.len() != 3 {
        return Err(CoreError::new(
            CoreErrorCode::MalformedJws,
            "compact JWS must have exactly three dot-separated parts",
        ));
    }
    let payload = b64_decode(parts[1])?;
    serde_json::from_slice(&payload).map_err(json_error)
}

fn remove_claim_at_path(
    value: &mut Value,
    object_path: &[String],
    claim_name: &str,
) -> CoreResult<Value> {
    object_at_path_mut(value, object_path)?
        .remove(claim_name)
        .ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::InvalidInput,
                format!("claim not found at {}: {claim_name}", object_path.join(".")),
            )
        })
}

fn set_object_value_at_path(
    value: &mut Value,
    object_path: &[String],
    key: String,
    item: Value,
) -> CoreResult<()> {
    object_at_path_mut(value, object_path)?.insert(key, item);
    Ok(())
}

fn push_sd_digest_at_path(
    value: &mut Value,
    object_path: &[String],
    digest: String,
) -> CoreResult<()> {
    let object = object_at_path_mut(value, object_path)?;
    match object.entry("_sd".to_owned()) {
        serde_json::map::Entry::Vacant(entry) => {
            entry.insert(Value::Array(vec![Value::String(digest)]));
        }
        serde_json::map::Entry::Occupied(mut entry) => {
            let Value::Array(array) = entry.get_mut() else {
                return Err(CoreError::new(
                    CoreErrorCode::InvalidInput,
                    "_sd must be an array",
                ));
            };
            array.push(Value::String(digest));
        }
    }
    Ok(())
}

fn object_at_path_mut<'a>(
    mut value: &'a mut Value,
    object_path: &[String],
) -> CoreResult<&'a mut Map<String, Value>> {
    for component in object_path {
        value = value.get_mut(component).ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::InvalidInput,
                format!("object path component not found: {component}"),
            )
        })?;
    }
    value.as_object_mut().ok_or_else(|| {
        CoreError::new(
            CoreErrorCode::InvalidInput,
            format!("path is not a JSON object: {}", object_path.join(".")),
        )
    })
}

fn sort_all_sd_digest_arrays(value: &mut Value) -> CoreResult<()> {
    match value {
        Value::Object(object) => {
            if let Some(sd) = object.get_mut("_sd") {
                let Value::Array(sd_array) = sd else {
                    return Err(CoreError::new(
                        CoreErrorCode::InvalidInput,
                        "_sd must be an array",
                    ));
                };
                let mut digests = Vec::with_capacity(sd_array.len());
                for digest in sd_array.iter() {
                    let Some(digest) = digest.as_str() else {
                        return Err(CoreError::new(
                            CoreErrorCode::InvalidInput,
                            "_sd entries must be strings",
                        ));
                    };
                    digests.push(digest.to_owned());
                }
                digests.sort();
                *sd_array = digests.into_iter().map(Value::String).collect();
            }
            for item in object.values_mut() {
                sort_all_sd_digest_arrays(item)?;
            }
        }
        Value::Array(array) => {
            for item in array {
                sort_all_sd_digest_arrays(item)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn find_sd_digest_path(value: &Value, digest: &str) -> Option<Vec<String>> {
    fn walk(value: &Value, digest: &str, path: &mut Vec<String>) -> Option<Vec<String>> {
        match value {
            Value::Object(object) => {
                if object
                    .get("_sd")
                    .and_then(Value::as_array)
                    .is_some_and(|sd| sd.iter().any(|item| item.as_str() == Some(digest)))
                {
                    return Some(path.clone());
                }
                for (key, item) in object {
                    if key == "_sd" {
                        continue;
                    }
                    path.push(key.clone());
                    if let Some(found) = walk(item, digest, path) {
                        return Some(found);
                    }
                    path.pop();
                }
            }
            Value::Array(array) => {
                for (index, item) in array.iter().enumerate() {
                    path.push(index.to_string());
                    if let Some(found) = walk(item, digest, path) {
                        return Some(found);
                    }
                    path.pop();
                }
            }
            _ => {}
        }
        None
    }

    walk(value, digest, &mut Vec::new())
}

fn apply_disclosures(
    payload: &mut Value,
    disclosures: &[DecodedDisclosure],
) -> CoreResult<Vec<Vec<String>>> {
    let mut pending = disclosures.iter().collect::<Vec<_>>();
    let mut applied_paths = Vec::with_capacity(disclosures.len());
    while !pending.is_empty() {
        let mut applied_any = false;
        let mut index = 0;
        while index < pending.len() {
            if let Some(path) = try_apply_disclosure(payload, pending[index])? {
                applied_paths.push(path);
                pending.remove(index);
                applied_any = true;
            } else {
                index += 1;
            }
        }
        if !applied_any {
            return Err(CoreError::new(
                CoreErrorCode::DisclosureDigestMismatch,
                "disclosure digest is not present in issuer payload",
            ));
        }
    }
    Ok(applied_paths)
}

fn try_apply_disclosure(
    payload: &mut Value,
    disclosure: &DecodedDisclosure,
) -> CoreResult<Option<Vec<String>>> {
    if disclosure.array_element {
        return Ok(replace_array_digest(
            payload,
            &disclosure.digest,
            &disclosure.claim_value,
            &mut Vec::new(),
        ));
    }
    let Some(object_path) = find_sd_digest_path(payload, &disclosure.digest) else {
        return Ok(None);
    };
    let object = object_at_path_mut(payload, &object_path)?;
    if object.contains_key(&disclosure.claim_name) {
        return Err(CoreError::new(
            CoreErrorCode::DisclosureDigestMismatch,
            format!("claim already disclosed: {}", disclosure.claim_name),
        ));
    }
    object.insert(
        disclosure.claim_name.clone(),
        disclosure.claim_value.clone(),
    );
    let mut disclosed_path = object_path;
    disclosed_path.push(disclosure.claim_name.clone());
    Ok(Some(disclosed_path))
}

fn replace_array_digest(
    value: &mut Value,
    digest: &str,
    replacement: &Value,
    path: &mut Vec<String>,
) -> Option<Vec<String>> {
    match value {
        Value::Object(object) => {
            for (key, item) in object.iter_mut().filter(|(key, _)| key.as_str() != "_sd") {
                path.push(key.clone());
                if let Some(found) = replace_array_digest(item, digest, replacement, path) {
                    return Some(found);
                }
                path.pop();
            }
            None
        }
        Value::Array(array) => {
            for (index, item) in array.iter_mut().enumerate() {
                path.push(index.to_string());
                let is_target = item.as_object().is_some_and(|object| {
                    object.len() == 1 && object.get("...").and_then(Value::as_str) == Some(digest)
                });
                if is_target {
                    *item = replacement.clone();
                    return Some(path.clone());
                }
                if let Some(found) = replace_array_digest(item, digest, replacement, path) {
                    return Some(found);
                }
                path.pop();
            }
            None
        }
        _ => None,
    }
}

fn ensure_sd_alg(payload: &Value) -> CoreResult<()> {
    match payload.get("_sd_alg") {
        None => Ok(()),
        Some(Value::String(algorithm)) if algorithm == SD_ALG_SHA_256 => Ok(()),
        Some(_) => Err(CoreError::new(
            CoreErrorCode::UnsupportedAlgorithm,
            "SD-JWT _sd_alg must be sha-256 when present",
        )),
    }
}

fn ensure_issuer_jwt_validity(payload: &Value, now_unix_seconds: i64) -> CoreResult<()> {
    let iat = optional_numeric_date(payload, "iat")?;
    let nbf = optional_numeric_date(payload, "nbf")?;
    let exp = optional_numeric_date(payload, "exp")?;
    let now = now_unix_seconds as f64;
    let future_boundary = (now_unix_seconds + ISSUER_JWT_MAX_FUTURE_NBF_SKEW_SECONDS) as f64;
    if iat.is_some_and(|value| value > future_boundary) {
        return Err(CoreError::new(
            CoreErrorCode::FreshnessCheckFailed,
            "issuer JWT iat is beyond the permitted future skew",
        ));
    }
    if nbf.is_some_and(|value| value > future_boundary) {
        return Err(CoreError::new(
            CoreErrorCode::FreshnessCheckFailed,
            "issuer JWT nbf is beyond the permitted future skew",
        ));
    }
    if exp.is_some_and(|value| value <= now) {
        return Err(CoreError::new(
            CoreErrorCode::FreshnessCheckFailed,
            "issuer JWT exp is not after verifier time",
        ));
    }
    if nbf
        .zip(exp)
        .is_some_and(|(not_before, expires)| not_before >= expires)
    {
        return Err(CoreError::new(
            CoreErrorCode::FreshnessCheckFailed,
            "issuer JWT validity interval is inverted",
        ));
    }
    Ok(())
}

fn optional_numeric_date(payload: &Value, name: &str) -> CoreResult<Option<f64>> {
    match payload.get(name) {
        None => Ok(None),
        Some(Value::Number(value)) => value
            .as_f64()
            .filter(|date| date.is_finite())
            .map(Some)
            .ok_or_else(|| {
                CoreError::new(
                    CoreErrorCode::FreshnessCheckFailed,
                    format!("issuer JWT {name} is not a finite numeric NumericDate"),
                )
            }),
        Some(_) => Err(CoreError::new(
            CoreErrorCode::FreshnessCheckFailed,
            format!("issuer JWT {name} is not a finite numeric NumericDate"),
        )),
    }
}

fn holder_jwk_from_payload(payload: &Value) -> CoreResult<PublicJwk> {
    let jwk = payload
        .get("cnf")
        .and_then(|cnf| cnf.get("jwk"))
        .ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::BindingCheckFailed,
                "issuer payload is missing cnf.jwk holder key",
            )
        })?;
    serde_json::from_value(jwk.clone()).map_err(json_error)
}

fn verify_kb_claims(
    issuer_jwt: &str,
    disclosures: &[&str],
    claims: &KbJwtClaims,
    options: &SdJwtVerificationOptions,
) -> CoreResult<()> {
    let disclosed_sd_jwt = format!(
        "{}{}~",
        issuer_jwt,
        disclosures
            .iter()
            .map(|disclosure| format!("~{disclosure}"))
            .collect::<String>()
    );
    if claims.sd_hash != sha256_b64url(disclosed_sd_jwt.as_bytes()) {
        return Err(CoreError::new(
            CoreErrorCode::BindingCheckFailed,
            "KB-JWT sd_hash does not match disclosed SD-JWT",
        ));
    }
    if claims.aud != options.audience {
        return Err(CoreError::new(
            CoreErrorCode::BindingCheckFailed,
            "KB-JWT audience mismatch",
        ));
    }
    if claims.nonce != options.nonce {
        return Err(CoreError::new(
            CoreErrorCode::BindingCheckFailed,
            "KB-JWT nonce mismatch",
        ));
    }
    if options.max_kb_age_seconds < 0 || options.max_kb_future_skew_seconds < 0 {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "KB-JWT freshness windows must be non-negative",
        ));
    }
    let earliest_accepted_iat = options
        .now_unix_seconds
        .saturating_sub(options.max_kb_age_seconds);
    let latest_accepted_iat = options
        .now_unix_seconds
        .saturating_add(options.max_kb_future_skew_seconds);
    if claims.iat < earliest_accepted_iat || claims.iat > latest_accepted_iat {
        return Err(CoreError::new(
            CoreErrorCode::FreshnessCheckFailed,
            "KB-JWT iat is outside verifier freshness window",
        ));
    }
    Ok(())
}

fn ensure_did_web(did: &str) -> CoreResult<()> {
    if did.strip_prefix(DID_WEB_METHOD_PREFIX).is_none() {
        return Err(CoreError::new(
            CoreErrorCode::InvalidInput,
            "DID must use the did:web method",
        ));
    }
    Ok(())
}

fn did_method_id(did: &str, kid: Option<&str>, index: usize) -> String {
    match kid {
        Some(kid) if kid.starts_with("did:") => kid.to_owned(),
        Some(kid) if kid.starts_with('#') => format!("{did}{kid}"),
        Some(kid) if !kid.is_empty() => format!("{did}#{kid}"),
        _ => format!("{did}#key-{}", index + 1),
    }
}

fn did_kid_candidates(issuer_did: &str, kid: &str) -> Vec<String> {
    let mut candidates = vec![kid.to_owned()];
    if let Some(fragment) = kid.strip_prefix('#') {
        candidates.push(format!("{issuer_did}#{fragment}"));
        candidates.push(fragment.to_owned());
    } else if !kid.starts_with("did:") && !kid.contains('#') {
        candidates.push(format!("{issuer_did}#{kid}"));
        candidates.push(format!("#{kid}"));
    } else if let Some(fragment) = kid.strip_prefix(&format!("{issuer_did}#")) {
        candidates.push(format!("#{fragment}"));
        candidates.push(fragment.to_owned());
    }
    candidates.sort();
    candidates.dedup();
    candidates
}

fn resolve_issuer_key_for_jws(
    compact_jws: &str,
    resolver: &impl HttpResolver,
) -> CoreResult<PublicJwk> {
    let parts: Vec<&str> = compact_jws.split('.').collect();
    if parts.len() != 3 {
        return Err(CoreError::new(
            CoreErrorCode::MalformedJws,
            "compact JWS must have exactly three dot-separated parts",
        ));
    }
    let header: JwsHeader = decode_json_segment(parts[0])?;
    let kid = header.kid.as_deref().ok_or_else(|| {
        CoreError::new(
            CoreErrorCode::KeyNotFound,
            "issuer JWS header is missing kid for did:web resolution",
        )
    })?;
    let payload = decode_jws_payload_unverified(compact_jws)?;
    let issuer_did = issuer_did_from_payload(&payload)?;
    resolve_did_web_key(issuer_did, kid, resolver)
}

fn issuer_did_from_payload(payload: &Value) -> CoreResult<&str> {
    let issuer = payload
        .get("iss")
        .and_then(Value::as_str)
        .or_else(|| payload.get("issuer").and_then(Value::as_str))
        .or_else(|| {
            payload
                .get("issuer")
                .and_then(|issuer| issuer.get("id"))
                .and_then(Value::as_str)
        })
        .ok_or_else(|| {
            CoreError::new(
                CoreErrorCode::InvalidInput,
                "issuer payload is missing iss or issuer id",
            )
        })?;
    ensure_did_web(issuer)?;
    Ok(issuer)
}

fn value_at_path<'a>(mut value: &'a Value, path: &[String]) -> Option<&'a Value> {
    for component in path {
        value = value.get(component)?;
    }
    Some(value)
}

fn encode_json_segment<T: Serialize>(value: &T) -> CoreResult<String> {
    serde_json::to_vec(value)
        .map(|json| b64_encode(&json))
        .map_err(json_error)
}

fn decode_json_segment<T: DeserializeOwned>(segment: &str) -> CoreResult<T> {
    let json = b64_decode(segment)?;
    serde_json::from_slice(&json).map_err(json_error)
}

fn json_error(error: serde_json::Error) -> CoreError {
    CoreError::new(CoreErrorCode::JsonSerialization, error.to_string())
}

fn public_jwk_from_verifying_key(verifying_key: &VerifyingKey, kid: Option<String>) -> PublicJwk {
    let point = verifying_key.to_sec1_point(false);
    let x = point
        .x()
        .expect("uncompressed P-256 point has x coordinate");
    let y = point
        .y()
        .expect("uncompressed P-256 point has y coordinate");

    PublicJwk::p256(b64_encode(x), b64_encode(y), kid)
}

fn verifying_key_from_jwk(jwk: &PublicJwk) -> CoreResult<VerifyingKey> {
    if jwk.kty != "EC" || jwk.crv != "P-256" {
        return Err(CoreError::new(
            CoreErrorCode::InvalidKey,
            "JWK must be an EC P-256 public key",
        ));
    }

    let x = b64_decode(&jwk.x)?;
    let y = b64_decode(&jwk.y)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(CoreError::new(
            CoreErrorCode::InvalidKey,
            "P-256 JWK coordinates must be 32 bytes each",
        ));
    }

    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);

    VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|_| CoreError::new(CoreErrorCode::InvalidKey, "invalid P-256 public point"))
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::{SigningKey, signature::Signer as _};
    use rcgen::CustomExtension;
    use serde_json::json;

    use super::*;

    const TEST_PRIVATE_SCALAR: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const TEST_HOLDER_PRIVATE_SCALAR: [u8; 32] = [
        0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
        0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
        0x01, 0x01,
    ];
    const WEBAPP_FIXTURE: &str = include_str!("../../../usecases/webapp-explainer/example.json");
    const RFC9901_ISSUER_JWK_X: &str = "b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ";
    const RFC9901_ISSUER_JWK_Y: &str = "Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8";
    const RFC9901_ISSUER_SEC1: [u8; 65] = [
        0x04, 0x6f, 0x6f, 0x1d, 0xe0, 0xcc, 0x19, 0x32, 0x3c, 0x3c, 0xfb, 0x4d, 0x02, 0x1b, 0x8c,
        0x5f, 0x9e, 0x7f, 0x52, 0x2c, 0xc5, 0x4c, 0x33, 0x5f, 0x52, 0x96, 0xa6, 0x69, 0x55, 0xbf,
        0xee, 0x36, 0xd4, 0x5e, 0xfe, 0x73, 0x5b, 0x0b, 0xa8, 0x69, 0x38, 0x1d, 0x4b, 0xa8, 0x55,
        0xe3, 0x7c, 0x88, 0xea, 0x00, 0x70, 0x4e, 0x78, 0xee, 0x92, 0x61, 0x50, 0x42, 0x72, 0x7f,
        0x90, 0x2c, 0x73, 0xaa, 0x4f,
    ];

    #[test]
    fn sd_jwt_defaults_absent_hash_algorithm_to_sha_256() {
        assert!(ensure_sd_alg(&json!({})).is_ok());
        assert!(ensure_sd_alg(&json!({"_sd_alg": "sha-256"})).is_ok());
        assert_eq!(
            ensure_sd_alg(&json!({"_sd_alg": "sha-512"}))
                .unwrap_err()
                .code(),
            CoreErrorCode::UnsupportedAlgorithm
        );
    }

    #[test]
    fn sd_jwt_credential_validity_claims_are_typed_and_current() {
        let issuer = TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, "issuer-1").unwrap();
        let holder =
            TestP256Signer::from_private_scalar(&TEST_HOLDER_PRIVATE_SCALAR, "holder-1").unwrap();
        let header = JwsHeader::es256(Some(DC_SD_JWT_TYP.to_owned()), Some("issuer-1".to_owned()));
        let options = SdJwtCredentialVerificationOptions {
            now_unix_seconds: 1_783_000_100,
            required_claims: Vec::new(),
            format: CredentialFormat::IetfSdJwtVc,
        };
        let verify = |extra: Value, removed: &[&str]| {
            let mut payload = json!({
                "iss": "https://issuer.example",
                "vct": "urn:eudi:pid:1",
                "iat": 1_783_000_000,
                "exp": 1_783_000_400,
                "cnf": {"jwk": holder.public_jwk}
            });
            for (name, value) in extra.as_object().unwrap() {
                payload[name] = value.clone();
            }
            for name in removed {
                payload.as_object_mut().unwrap().remove(*name);
            }
            let mut salts = FixedSaltSource::new(std::iter::empty::<Vec<u8>>());
            let issued = issue_sd_jwt_with_format(
                payload,
                &[],
                &header,
                &issuer,
                &issuer.key_id,
                &mut salts,
                SdJwtIssueOptions {
                    decoy_digests: 0,
                    format: CredentialFormat::IetfSdJwtVc,
                },
            )
            .unwrap();
            verify_sd_jwt_credential(&issued.compact, &issuer.public_jwk, &options)
        };

        verify(json!({"nbf": 1_783_000_160}), &[]).unwrap();
        verify(json!({}), &["iat"]).unwrap();
        verify(
            json!({
                "iat": 1_783_000_000.5,
                "nbf": 1_783_000_159.5,
                "exp": 1_783_000_400.5
            }),
            &[],
        )
        .unwrap();
        for invalid in [
            json!({"nbf": 1_783_000_161}),
            json!({"nbf": "soon"}),
            json!({"exp": "later"}),
            json!({"nbf": 1_783_000_200, "exp": 1_783_000_150}),
        ] {
            assert_eq!(
                verify(invalid, &[]).unwrap_err().code(),
                CoreErrorCode::FreshnessCheckFailed
            );
        }
    }

    #[test]
    fn w3c_sd_jwt_enforces_jwt_claim_and_key_identifier_rules() {
        let issuer = TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, "issuer-1").unwrap();
        let options = SdJwtCredentialVerificationOptions {
            now_unix_seconds: 1_783_000_000,
            required_claims: Vec::new(),
            format: CredentialFormat::W3cVcDataModel,
        };

        for mutate in [
            |payload: &mut Value| payload["iss"] = json!("https://different.example"),
            |payload: &mut Value| payload["vc"] = json!({}),
            |payload: &mut Value| payload["vp"] = json!({}),
            |payload: &mut Value| payload["jti"] = json!(7),
            |payload: &mut Value| {
                payload["id"] = json!("https://issuer.example/credentials/1");
                payload["jti"] = json!("https://issuer.example/credentials/2");
            },
            |payload: &mut Value| {
                payload["credentialSubject"]["id"] = json!("did:example:holder");
                payload["sub"] = json!("did:example:other");
            },
        ] {
            let mut payload = student_vector_payload(&issuer.public_jwk);
            mutate(&mut payload);
            let compact = format!("{}~", sign_test_jwt(VC_SD_JWT_TYP, &payload, &issuer));
            assert_eq!(
                verify_sd_jwt_credential(&compact, &issuer.public_jwk, &options)
                    .unwrap_err()
                    .code(),
                CoreErrorCode::InvalidInput
            );
        }

        let mut subject_without_id = student_vector_payload(&issuer.public_jwk);
        subject_without_id["credentialSubject"]
            .as_object_mut()
            .unwrap()
            .remove("id");
        subject_without_id["sub"] = json!("did:example:holder");
        let compact = format!(
            "{}~",
            sign_test_jwt(VC_SD_JWT_TYP, &subject_without_id, &issuer)
        );
        assert!(verify_sd_jwt_credential(&compact, &issuer.public_jwk, &options).is_ok());

        let absolute_key_id = "https://issuer.example/keys/1";
        let absolute_issuer =
            TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, absolute_key_id).unwrap();
        let mut without_iss = student_vector_payload(&absolute_issuer.public_jwk);
        without_iss.as_object_mut().unwrap().remove("iss");
        let header = JwsHeader::es256(
            Some(VC_SD_JWT_TYP.to_owned()),
            Some(absolute_key_id.to_owned()),
        );
        let mut salts = FixedSaltSource::new(std::iter::empty::<Vec<u8>>());
        assert!(
            issue_sd_jwt(
                without_iss.clone(),
                &[],
                0,
                &header,
                &absolute_issuer,
                &absolute_issuer.key_id,
                &mut salts,
            )
            .is_ok()
        );

        let relative_issuer =
            TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, "issuer-1").unwrap();
        let relative_header =
            JwsHeader::es256(Some(VC_SD_JWT_TYP.to_owned()), Some("issuer-1".to_owned()));
        let mut salts = FixedSaltSource::new(std::iter::empty::<Vec<u8>>());
        assert_eq!(
            issue_sd_jwt(
                without_iss,
                &[],
                0,
                &relative_header,
                &relative_issuer,
                &relative_issuer.key_id,
                &mut salts,
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::InvalidInput
        );

        let mut wrong_cty =
            JwsHeader::es256(Some(VC_SD_JWT_TYP.to_owned()), Some("issuer-1".to_owned()));
        wrong_cty.cty = Some("vp".to_owned());
        let mut salts = FixedSaltSource::new(std::iter::empty::<Vec<u8>>());
        assert_eq!(
            issue_sd_jwt(
                student_vector_payload(&relative_issuer.public_jwk),
                &[],
                0,
                &wrong_cty,
                &relative_issuer,
                &relative_issuer.key_id,
                &mut salts,
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::InvalidInput
        );

        for disclosure in [
            DisclosureSpec {
                object_path: Vec::new(),
                claim_name: "type".to_owned(),
            },
            DisclosureSpec {
                object_path: Vec::new(),
                claim_name: "validFrom".to_owned(),
            },
            DisclosureSpec {
                object_path: Vec::new(),
                claim_name: "validUntil".to_owned(),
            },
            DisclosureSpec {
                object_path: vec!["credentialStatus".to_owned()],
                claim_name: "statusListIndex".to_owned(),
            },
        ] {
            let mut salts = FixedSaltSource::new([vec![0_u8; SD_JWT_SALT_BYTES]]);
            let header =
                JwsHeader::es256(Some(VC_SD_JWT_TYP.to_owned()), Some("issuer-1".to_owned()));
            assert_eq!(
                issue_sd_jwt(
                    student_vector_payload(&relative_issuer.public_jwk),
                    &[disclosure],
                    0,
                    &header,
                    &relative_issuer,
                    &relative_issuer.key_id,
                    &mut salts,
                )
                .unwrap_err()
                .code(),
                CoreErrorCode::InvalidInput
            );
        }
    }

    #[test]
    fn sd_jwt_materializes_nested_array_disclosures_in_any_order() {
        let array_disclosure = b64_encode(br#"["array-salt","AU"]"#);
        let array_digest = sha256_b64url(array_disclosure.as_bytes());
        let object_disclosure = encode_disclosure(
            "object-salt",
            "nationalities",
            &json!([{"...": array_digest}]),
        )
        .unwrap();
        let object_digest = sha256_b64url(object_disclosure.as_bytes());
        let mut payload = json!({"_sd": [object_digest]});
        let disclosures = [
            decode_disclosure(&array_disclosure).unwrap(),
            decode_disclosure(&object_disclosure).unwrap(),
        ];

        apply_disclosures(&mut payload, &disclosures).unwrap();

        assert_eq!(payload["nationalities"], json!(["AU"]));
    }

    #[test]
    fn oid4vci_jwe_round_trips_and_rejects_tampering_or_critical_headers() {
        let recipient = SecretKey::from_slice(&TEST_PRIVATE_SCALAR).unwrap();
        let ephemeral = SecretKey::from_slice(&TEST_HOLDER_PRIVATE_SCALAR).unwrap();
        let parameters = Oid4vciCredentialResponseEncryption {
            jwk: JwePublicJwk::from_public_key(
                recipient.public_key(),
                Some("wallet-encryption-key".to_owned()),
                Some("ECDH-ES".to_owned()),
            ),
            enc: "A256GCM".to_owned(),
            zip: Some("DEF".to_owned()),
        };
        let plaintext = json!({"credentials": [{"credential": "private-value"}]});
        let encrypted = encrypt_oid4vci_jwe_with_material(
            &plaintext,
            &parameters,
            &ephemeral,
            &[7_u8; OID4VCI_JWE_IV_BYTES],
        )
        .unwrap();
        assert_eq!(
            decrypt_oid4vci_jwe(&encrypted, &recipient, Some("wallet-encryption-key")).unwrap(),
            plaintext
        );

        let mut tampered = encrypted.clone();
        let replacement = if tampered.ends_with('A') { 'B' } else { 'A' };
        tampered.pop();
        tampered.push(replacement);
        assert_eq!(
            decrypt_oid4vci_jwe(&tampered, &recipient, Some("wallet-encryption-key"))
                .unwrap_err()
                .code(),
            CoreErrorCode::VerificationFailed
        );

        let mut parts = encrypted.split('.').map(str::to_owned).collect::<Vec<_>>();
        let mut header: Value = decode_json_segment(&parts[0]).unwrap();
        header["crit"] = json!(["unsupported"]);
        parts[0] = encode_json_segment(&header).unwrap();
        assert_eq!(
            decrypt_oid4vci_jwe(&parts.join("."), &recipient, Some("wallet-encryption-key"))
                .unwrap_err()
                .code(),
            CoreErrorCode::UnsupportedAlgorithm
        );
    }

    #[test]
    fn oid4vci_jwe_public_key_type_rejects_private_members() {
        assert!(
            serde_json::from_value::<JwePublicJwk>(json!({
                "kty": "EC",
                "crv": "P-256",
                "x": "x",
                "y": "y",
                "d": "private"
            }))
            .is_err()
        );
    }

    #[derive(Clone, Debug)]
    struct TestP256Signer {
        key_id: KeyId,
        signing_key: SigningKey,
        public_jwk: PublicJwk,
    }

    impl TestP256Signer {
        fn from_private_scalar(
            private_scalar: &[u8],
            key_id: impl Into<String>,
        ) -> CoreResult<Self> {
            let key_id = KeyId::new(key_id);
            let signing_key = SigningKey::from_slice(private_scalar).map_err(|_| {
                CoreError::new(CoreErrorCode::InvalidKey, "invalid P-256 private scalar")
            })?;
            let public_jwk =
                public_jwk_from_verifying_key(signing_key.verifying_key(), Some(key_id.0.clone()));
            Ok(Self {
                key_id,
                signing_key,
                public_jwk,
            })
        }

        fn sign_es256(&self, signing_input: &[u8]) -> Vec<u8> {
            let signature: Signature = self.signing_key.sign(signing_input);
            signature.to_bytes().to_vec()
        }
    }

    impl Signer for TestP256Signer {
        fn sign(&self, key_id: &KeyId, signing_input: &[u8]) -> CoreResult<Vec<u8>> {
            if key_id != &self.key_id {
                return Err(CoreError::new(
                    CoreErrorCode::KeyNotFound,
                    "test key missing",
                ));
            }

            Ok(self.sign_es256(signing_input))
        }
    }

    fn sign_test_jwt(typ: &str, claims: &Value, signer: &TestP256Signer) -> String {
        sign_compact_jws_json(
            &JwsHeader {
                alg: "ES256".to_owned(),
                typ: Some(typ.to_owned()),
                cty: None,
                kid: Some(signer.key_id.as_str().to_owned()),
                jwk: None,
                x5c: None,
            },
            claims,
            signer,
            &signer.key_id,
        )
        .unwrap()
    }

    fn sign_test_jwt_with_header(
        header: &Value,
        claims: &Value,
        signer: &TestP256Signer,
    ) -> String {
        let protected = encode_json_segment(header).unwrap();
        let payload = encode_json_segment(claims).unwrap();
        let signing_input = format!("{protected}.{payload}");
        let signature = signer.sign_es256(signing_input.as_bytes());
        format!("{signing_input}.{}", b64_encode(&signature))
    }

    #[derive(Clone, Debug)]
    struct FixedResolver {
        url: String,
        body: Vec<u8>,
    }

    impl HttpResolver for FixedResolver {
        fn resolve(&self, url: &str) -> CoreResult<Vec<u8>> {
            if url != self.url {
                return Err(CoreError::new(
                    CoreErrorCode::ResolverUnavailable,
                    format!("unexpected resolver URL: {url}"),
                ));
            }
            Ok(self.body.clone())
        }
    }

    fn student_vector_payload(holder_jwk: &PublicJwk) -> Value {
        json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "UniversityEducationCredential"],
            "iss": "https://issuer.unsw.edu.au",
            "issuer": "https://issuer.unsw.edu.au",
            "iat": 1783000000,
            "exp": 1883000000,
            "validFrom": "2026-07-01T00:00:00Z",
            "validUntil": "2027-07-01T00:00:00Z",
            "credentialSubject": {
                "institution_id": "unsw.edu.au",
                "enrolled": true,
                "affiliation": "student",
                "family_name": "Citizen",
                "given_name": "Avery",
                "student_id": "z5555555",
                "program": "BSc Computer Science",
                "date_of_birth": "2001-02-03",
                "photo_hash": "6EoT5S7F9B0x3uYcSO7tmQeI6dAUcFxxS4M1blj6Vb0"
            },
            "credentialStatus": {
                "id": "https://status.unsw.example/status/1#42",
                "type": "BitstringStatusListEntry",
                "statusPurpose": "revocation",
                "statusListIndex": "42",
                "statusListCredential": "https://status.unsw.example/status/1"
            },
            "cnf": {
                "jwk": holder_jwk
            }
        })
    }

    fn student_disclosure_specs() -> Vec<DisclosureSpec> {
        [
            "enrolled",
            "affiliation",
            "family_name",
            "given_name",
            "student_id",
            "program",
            "date_of_birth",
            "photo_hash",
        ]
        .into_iter()
        .map(|claim_name| DisclosureSpec::new(["credentialSubject"], claim_name))
        .collect()
    }

    fn fixture_value() -> Value {
        serde_json::from_str(WEBAPP_FIXTURE).expect("fixture is valid JSON")
    }

    fn fixture_issuer_jwk(fixture: &Value) -> PublicJwk {
        serde_json::from_value(fixture["issuer_public_jwk"].clone()).unwrap()
    }

    fn fixed_salts_from_fixture(fixture: &Value) -> FixedSaltSource {
        FixedSaltSource::new(
            fixture["disclosures"]
                .as_array()
                .unwrap()
                .iter()
                .map(|disclosure| {
                    b64_decode(disclosure["salt_bytes"].as_str().unwrap())
                        .expect("fixture salt is base64url")
                }),
        )
    }

    fn status_list_payload(encoded_list: String) -> BitstringStatusListCredentialPayload {
        BitstringStatusListCredentialPayload {
            context: vec![
                "https://www.w3.org/ns/credentials/v2".to_owned(),
                "https://www.w3.org/ns/credentials/status/v1".to_owned(),
            ],
            type_: vec![
                "VerifiableCredential".to_owned(),
                "BitstringStatusListCredential".to_owned(),
            ],
            issuer: "did:web:issuer.unsw.example.edu.au".to_owned(),
            credential_subject: BitstringStatusListSubject {
                id: "https://status.unsw.example/status/1#list".to_owned(),
                type_: "BitstringStatusList".to_owned(),
                status_purpose: "revocation".to_owned(),
                encoded_list,
            },
            valid_from: Some("2026-07-01T00:00:00Z".to_owned()),
            valid_until: Some("2027-07-01T00:00:00Z".to_owned()),
        }
    }

    fn status_entry(index: usize) -> CredentialStatus {
        CredentialStatus {
            id: format!("https://status.unsw.example/status/1#{index}"),
            type_: "BitstringStatusListEntry".to_owned(),
            status_purpose: "revocation".to_owned(),
            status_list_index: index.to_string(),
            status_list_credential: "https://status.unsw.example/status/1".to_owned(),
        }
    }

    fn signed_trust_list(
        trust_anchor: &TestP256Signer,
        student_issuer: &TestP256Signer,
        status: TrustListStatus,
    ) -> String {
        sign_trust_list(
            &trust_list_payload(student_issuer, status),
            &JwsHeader::es256(
                Some("trust-list+jwt".to_owned()),
                Some("trust-anchor-1".to_owned()),
            ),
            trust_anchor,
            &trust_anchor.key_id,
        )
        .unwrap()
    }

    fn trust_list_payload(
        student_issuer: &TestP256Signer,
        status: TrustListStatus,
    ) -> TrustListPayload {
        TrustListPayload {
            id: "https://trust.unsw.example/trust-list.jwt".to_owned(),
            issuer: "did:web:trust.unsw.example".to_owned(),
            iat: 1_783_376_000,
            exp: 1_783_400_000,
            entries: vec![TrustListEntry {
                issuer_did: "did:web:issuer.unsw.example.edu.au".to_owned(),
                credential_types: vec!["UniversityEducationCredential".to_owned()],
                status,
                public_jwk: Some(student_issuer.public_jwk.clone()),
                public_jwk_sha256_thumbprint: Some(
                    public_jwk_sha256_thumbprint(&student_issuer.public_jwk).unwrap(),
                ),
            }],
            verifiers: vec![VerifierTrustListEntry {
                verifier_did: "did:web:study-space.example".to_owned(),
                credential_type: "UniversityEducationCredential".to_owned(),
                profile_name: "uc3_study_space".to_owned(),
                claim_paths: vec![
                    vec!["credentialSubject".to_owned(), "enrolled".to_owned()],
                    vec!["credentialSubject".to_owned(), "institution_id".to_owned()],
                ],
                status: TrustListStatus::Active,
            }],
        }
    }

    fn oid4vp_request_payload(verifier_did: &str) -> Value {
        json!({
            "client_id": format!("decentralized_identifier:{verifier_did}"),
            "aud": "https://self-issued.me/v2",
            "iat": 1_783_000_000,
            "exp": 1_783_000_300,
            "nonce": "eXBlY3RlZC1mcmVzaC1ub25jZQ",
            "response_mode": "direct_post",
            "response_type": "vp_token",
            "response_uri": "https://study-space.example/oid4vp/response",
            "state": "study-space-session-1",
            "dcql_query": {
                "credentials": [{
                    "id": "uc3_study_space",
                    "format": "vc+sd-jwt",
                    "meta": {
                        "type_values": [[
                            "VerifiableCredential",
                            "UniversityEducationCredential"
                        ]]
                    },
                    "claims": [
                        {"path": ["credentialSubject", "enrolled"]},
                        {"path": ["credentialSubject", "institution_id"]}
                    ]
                }]
            }
        })
    }

    fn oidf_wallet_payload(client_id: &str, profile: Oid4vpWalletInteropProfile) -> Value {
        let encryption =
            TestP256Signer::from_private_scalar(&TEST_HOLDER_PRIVATE_SCALAR, "response-encryption")
                .unwrap();
        let mut payload = json!({
            "client_id": client_id,
            "aud": "https://self-issued.me/v2",
            "nonce": "oidf-wallet-nonce-123456",
            "response_type": "vp_token",
            "response_mode": if profile == Oid4vpWalletInteropProfile::Haip {
                "direct_post.jwt"
            } else {
                "direct_post"
            },
            "response_uri": "https://localhost.emobix.co.uk:8443/test/a/plan/responseuri",
            "state": "oidf-wallet-state",
            "client_metadata": {
                "vp_formats_supported": {
                    "dc+sd-jwt": {
                        "sd-jwt_alg_values": ["ES256"],
                        "kb-jwt_alg_values": ["ES256"]
                    }
                }
            },
            "dcql_query": {
                "credentials": [{
                    "id": "my_credential",
                    "format": "dc+sd-jwt",
                    "meta": {"vct_values": ["urn:eudi:pid:1"]},
                    "claims": [
                        {"path": ["given_name"]},
                        {"path": ["family_name"]}
                    ]
                }]
            }
        });
        if profile == Oid4vpWalletInteropProfile::Haip {
            payload["client_metadata"]["encrypted_response_enc_values_supported"] =
                json!(["A256GCM"]);
            payload["client_metadata"]["jwks"] = json!({
                "keys": [{
                    "kty": "EC",
                    "crv": "P-256",
                    "x": encryption.public_jwk.x,
                    "y": encryption.public_jwk.y,
                    "kid": "response-encryption",
                    "alg": "ECDH-ES",
                    "use": "enc"
                }]
            });
        }
        payload
    }

    fn oidf_wallet_available_claims() -> BTreeMap<String, Value> {
        BTreeMap::from([
            ("given_name".to_owned(), json!("OIDF")),
            ("family_name".to_owned(), json!("Interop")),
        ])
    }

    fn test_x509_identity_with_intermediate() -> DeterministicTestX509Identity {
        test_x509_identity_with_intermediate_options(BasicConstraints::Unconstrained, false, false)
    }

    fn test_x509_identity_with_intermediate_options(
        root_constraint: BasicConstraints,
        unsupported_critical_leaf_extension: bool,
        self_issued_intermediate: bool,
    ) -> DeterministicTestX509Identity {
        let leaf_signing_key = deterministic_test_issuer_signing_key(250).unwrap();
        let intermediate_signing_key = deterministic_test_issuer_signing_key(251).unwrap();
        let root_signing_key = deterministic_test_issuer_signing_key(254).unwrap();
        let leaf_key_pair = DeterministicRcgenP256Key::new(leaf_signing_key.clone());
        let intermediate_key_pair =
            DeterministicRcgenP256Key::new(intermediate_signing_key.clone());
        let root_key_pair = DeterministicRcgenP256Key::new(root_signing_key);

        let mut root_params = CertificateParams::default();
        root_params.distinguished_name = x509_common_name(if self_issued_intermediate {
            "OIDF rollover CA"
        } else {
            "OIDF test root"
        });
        root_params.is_ca = IsCa::Ca(root_constraint);
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        root_params.key_identifier_method =
            KeyIdMethod::PreSpecified(Sha256::digest(root_key_pair.der_bytes()).to_vec());
        root_params.serial_number = Some(SerialNumber::from(1_u64));
        let root_certificate = root_params.self_signed(&root_key_pair).unwrap();
        let root_issuer = Issuer::new(root_params, root_key_pair);

        let mut intermediate_params = CertificateParams::default();
        intermediate_params.distinguished_name = x509_common_name(if self_issued_intermediate {
            "OIDF rollover CA"
        } else {
            "OIDF test intermediate"
        });
        intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        intermediate_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        intermediate_params.key_identifier_method =
            KeyIdMethod::PreSpecified(Sha256::digest(intermediate_key_pair.der_bytes()).to_vec());
        intermediate_params.serial_number = Some(SerialNumber::from(2_u64));
        intermediate_params.use_authority_key_identifier_extension = true;
        let intermediate_certificate = intermediate_params
            .signed_by(&intermediate_key_pair, &root_issuer)
            .unwrap();
        let intermediate_issuer = Issuer::new(intermediate_params, intermediate_key_pair);

        let mut leaf_params = CertificateParams::default();
        leaf_params.distinguished_name = x509_common_name("OIDF test leaf");
        leaf_params.is_ca = IsCa::NoCa;
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.key_identifier_method =
            KeyIdMethod::PreSpecified(Sha256::digest(leaf_key_pair.der_bytes()).to_vec());
        leaf_params.serial_number = Some(SerialNumber::from(3_u64));
        leaf_params.use_authority_key_identifier_extension = true;
        if unsupported_critical_leaf_extension {
            let mut extension =
                CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 55555, 1], vec![5, 0]);
            extension.set_criticality(true);
            leaf_params.custom_extensions.push(extension);
        }
        let leaf_certificate = leaf_params
            .signed_by(&leaf_key_pair, &intermediate_issuer)
            .unwrap();

        DeterministicTestX509Identity {
            public_jwk: public_jwk_from_verifying_key(
                leaf_signing_key.verifying_key(),
                Some("oidf-test-leaf".to_owned()),
            ),
            x5c: vec![
                Base64::encode_string(leaf_certificate.der()),
                Base64::encode_string(intermediate_certificate.der()),
            ],
            trust_anchor_pem: root_certificate.pem(),
        }
    }

    #[test]
    fn defines_stable_binding_error_codes() {
        let serialized = serde_json::to_value(CoreErrorCode::InvalidSignature).unwrap();

        assert_eq!(serialized, json!("INVALID_SIGNATURE"));
    }

    #[test]
    fn sd_jwt_defaults_to_sha_256_when_sd_alg_is_absent() {
        ensure_sd_alg(&json!({})).unwrap();
        ensure_sd_alg(&json!({"_sd_alg": "sha-256"})).unwrap();

        assert_eq!(
            ensure_sd_alg(&json!({"_sd_alg": "sha-512"}))
                .unwrap_err()
                .code(),
            CoreErrorCode::UnsupportedAlgorithm
        );
    }

    #[test]
    fn fixed_salt_source_is_deterministic_and_exhaustive() {
        let mut salts = FixedSaltSource::new([vec![1; 16], vec![2; 16]]);

        assert_eq!(salts.salt(16).unwrap(), vec![1; 16]);
        assert_eq!(salts.salt(16).unwrap(), vec![2; 16]);
        assert_eq!(
            salts.salt(16).unwrap_err().code(),
            CoreErrorCode::SaltUnavailable
        );
    }

    #[test]
    fn p256_es256_signs_and_verifies_locally() {
        let signer = TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, "test-key").unwrap();
        let message = b"deterministic ES256 signing input";
        let signature = signer.sign_es256(message);
        let verifying_key = verifying_key_from_jwk(&signer.public_jwk).unwrap();
        let signature = Signature::from_slice(&signature).unwrap();

        verifying_key.verify(message, &signature).unwrap();
    }

    #[test]
    fn verifies_dpop_proof_signature_binding_freshness_and_access_token_hash() {
        let signer =
            TestP256Signer::from_private_scalar(&TEST_HOLDER_PRIVATE_SCALAR, "dpop-key").unwrap();
        let access_token = "opaque-access-token";
        let header = JwsHeader {
            alg: "ES256".to_owned(),
            typ: Some("dpop+jwt".to_owned()),
            cty: None,
            kid: None,
            jwk: Some(signer.public_jwk.clone()),
            x5c: None,
        };
        let payload = json!({
            "htu": "https://issuer.example/oid4vci/credential",
            "htm": "POST",
            "iat": 1_783_376_100,
            "jti": "dpop-proof-1",
            "ath": sha256_b64url(access_token.as_bytes()),
        });
        let proof = sign_compact_jws_json(&header, &payload, &signer, &signer.key_id).unwrap();
        let options = DpopVerificationOptions {
            expected_htu: "https://issuer.example/oid4vci/credential".to_owned(),
            expected_htm: "POST".to_owned(),
            now_unix_seconds: 1_783_376_120,
            max_age_seconds: 300,
            access_token: Some(access_token.to_owned()),
            expected_nonce: None,
        };

        let verified = verify_dpop_proof(&proof, &options).unwrap();
        assert_eq!(verified.jti, "dpop-proof-1");
        assert_eq!(verified.public_jwk, signer.public_jwk);
        assert_eq!(
            verified.public_jwk_sha256_thumbprint,
            public_jwk_sha256_thumbprint(&signer.public_jwk).unwrap(),
        );

        let normalized_uri_payload = json!({
            "htu": "HTTPS://ISSUER.EXAMPLE/oid4vci/credential?conformance=true#ignored",
            "htm": "POST",
            "iat": 1_783_376_100,
            "jti": "dpop-proof-normalized-uri",
            "ath": sha256_b64url(access_token.as_bytes()),
        });
        let normalized_uri_proof =
            sign_compact_jws_json(&header, &normalized_uri_payload, &signer, &signer.key_id)
                .unwrap();
        assert!(verify_dpop_proof(&normalized_uri_proof, &options).is_ok());

        let lowercase_method_payload = json!({
            "htu": "https://issuer.example/oid4vci/credential",
            "htm": "post",
            "iat": 1_783_376_100,
            "jti": "dpop-proof-lowercase-method",
            "ath": sha256_b64url(access_token.as_bytes()),
        });
        let lowercase_method_proof =
            sign_compact_jws_json(&header, &lowercase_method_payload, &signer, &signer.key_id)
                .unwrap();
        assert_eq!(
            verify_dpop_proof(&lowercase_method_proof, &options)
                .unwrap_err()
                .code(),
            CoreErrorCode::BindingCheckFailed,
        );

        let critical_header_proof = sign_test_jwt_with_header(
            &json!({
                "alg": "ES256",
                "typ": "dpop+jwt",
                "jwk": signer.public_jwk,
                "crit": ["unsupported-extension"],
                "unsupported-extension": true,
            }),
            &payload,
            &signer,
        );
        assert_eq!(
            verify_dpop_proof(&critical_header_proof, &options)
                .unwrap_err()
                .code(),
            CoreErrorCode::UnsupportedAlgorithm,
        );

        let private_header_segment = encode_json_segment(&json!({
            "alg": "ES256",
            "typ": "dpop+jwt",
            "jwk": {
                "kty": signer.public_jwk.kty,
                "crv": signer.public_jwk.crv,
                "x": signer.public_jwk.x,
                "y": signer.public_jwk.y,
                "d": "private-key-material-must-not-be-accepted",
            },
        }))
        .unwrap();
        let private_payload_segment = encode_json_segment(&payload).unwrap();
        let private_signing_input = format!("{private_header_segment}.{private_payload_segment}");
        let private_signature = signer.sign_es256(private_signing_input.as_bytes());
        let private_jwk_proof =
            format!("{private_signing_input}.{}", b64_encode(&private_signature),);
        assert_eq!(
            verify_dpop_proof(&private_jwk_proof, &options)
                .unwrap_err()
                .code(),
            CoreErrorCode::InvalidKey,
        );

        let future_boundary_payload = json!({
            "htu": "https://issuer.example/oid4vci/credential",
            "htm": "POST",
            "iat": options.now_unix_seconds + 10,
            "jti": "dpop-proof-future-boundary",
            "ath": sha256_b64url(access_token.as_bytes()),
        });
        let future_boundary_proof =
            sign_compact_jws_json(&header, &future_boundary_payload, &signer, &signer.key_id)
                .unwrap();
        assert!(verify_dpop_proof(&future_boundary_proof, &options).is_ok());

        let beyond_future_boundary_payload = json!({
            "htu": "https://issuer.example/oid4vci/credential",
            "htm": "POST",
            "iat": options.now_unix_seconds + 11,
            "jti": "dpop-proof-beyond-future-boundary",
            "ath": sha256_b64url(access_token.as_bytes()),
        });
        let beyond_future_boundary_proof = sign_compact_jws_json(
            &header,
            &beyond_future_boundary_payload,
            &signer,
            &signer.key_id,
        )
        .unwrap();
        assert_eq!(
            verify_dpop_proof(&beyond_future_boundary_proof, &options)
                .unwrap_err()
                .code(),
            CoreErrorCode::FreshnessCheckFailed,
        );

        let wrong_token = DpopVerificationOptions {
            access_token: Some("different-access-token".to_owned()),
            ..options.clone()
        };
        assert_eq!(
            verify_dpop_proof(&proof, &wrong_token).unwrap_err().code(),
            CoreErrorCode::BindingCheckFailed,
        );
        let stale = DpopVerificationOptions {
            now_unix_seconds: 1_783_376_500,
            ..options
        };
        assert_eq!(
            verify_dpop_proof(&proof, &stale).unwrap_err().code(),
            CoreErrorCode::FreshnessCheckFailed,
        );
    }

    #[test]
    fn verifies_oauth_client_attestation_and_instance_key_proof() {
        let attester =
            TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, "attester-key").unwrap();
        let instance =
            TestP256Signer::from_private_scalar(&TEST_HOLDER_PRIVATE_SCALAR, "client-instance-key")
                .unwrap();
        let attestation = sign_compact_jws_json(
            &JwsHeader {
                alg: "ES256".to_owned(),
                typ: Some("oauth-client-attestation+jwt".to_owned()),
                cty: None,
                kid: Some(attester.key_id.as_str().to_owned()),
                jwk: None,
                x5c: None,
            },
            &json!({
                "iss": "https://attester.example",
                "sub": "wallet-client",
                "iat": 1_783_376_100,
                "nbf": 1_783_376_100,
                "exp": 1_783_376_400,
                "cnf": { "jwk": instance.public_jwk },
            }),
            &attester,
            &attester.key_id,
        )
        .unwrap();
        let proof = sign_compact_jws_json(
            &JwsHeader {
                alg: "ES256".to_owned(),
                typ: Some("oauth-client-attestation-pop+jwt".to_owned()),
                cty: None,
                kid: Some(instance.key_id.as_str().to_owned()),
                jwk: None,
                x5c: None,
            },
            &json!({
                "iss": "wallet-client",
                "aud": "https://issuer.example",
                "iat": 1_783_376_110,
                "nbf": 1_783_376_110,
                "exp": 1_783_376_410,
                "jti": "client-proof-1",
            }),
            &instance,
            &instance.key_id,
        )
        .unwrap();
        let options = ClientAttestationVerificationOptions {
            trusted_attester_jwk: attester.public_jwk,
            expected_attester_issuer: "https://attester.example".to_owned(),
            expected_client_id: Some("wallet-client".to_owned()),
            expected_audience: "https://issuer.example".to_owned(),
            now_unix_seconds: 1_783_376_120,
            max_age_seconds: 300,
            expected_challenge: None,
        };

        let verified = verify_client_attestation(&attestation, &proof, &options).unwrap();
        assert_eq!(verified.client_id, "wallet-client");
        assert_eq!(verified.client_instance_jwk, instance.public_jwk);

        let inferred_client = ClientAttestationVerificationOptions {
            expected_client_id: None,
            ..options.clone()
        };
        assert_eq!(
            verify_client_attestation(&attestation, &proof, &inferred_client)
                .unwrap()
                .client_id,
            "wallet-client",
        );

        let wrong_audience = ClientAttestationVerificationOptions {
            expected_audience: "https://different.example".to_owned(),
            ..options
        };
        assert_eq!(
            verify_client_attestation(&attestation, &proof, &wrong_audience)
                .unwrap_err()
                .code(),
            CoreErrorCode::BindingCheckFailed,
        );
    }

    #[test]
    fn rejects_every_client_attestation_error_boundary() {
        let attester =
            TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, "attester-key").unwrap();
        let instance =
            TestP256Signer::from_private_scalar(&TEST_HOLDER_PRIVATE_SCALAR, "instance-key")
                .unwrap();
        let other = TestP256Signer::from_private_scalar(
            &[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x20,
            ],
            "other-key",
        )
        .unwrap();
        let now = 1_783_376_120;
        let options = ClientAttestationVerificationOptions {
            trusted_attester_jwk: attester.public_jwk.clone(),
            expected_attester_issuer: "https://attester.example".to_owned(),
            expected_client_id: Some("wallet-client".to_owned()),
            expected_audience: "https://issuer.example".to_owned(),
            now_unix_seconds: now,
            max_age_seconds: 300,
            expected_challenge: Some("attestation-challenge".to_owned()),
        };
        let attestation_claims = json!({
            "iss": "https://attester.example",
            "sub": "wallet-client",
            "iat": now - 20,
            "nbf": now - 20,
            "exp": now + 300,
            "cnf": { "jwk": instance.public_jwk },
        });
        let proof_claims = json!({
            "iss": "wallet-client",
            "aud": "https://issuer.example",
            "iat": now - 10,
            "nbf": now - 10,
            "exp": now + 300,
            "jti": "proof-jti",
            "challenge": "attestation-challenge",
        });
        let good_attestation = sign_test_jwt(
            "oauth-client-attestation+jwt",
            &attestation_claims,
            &attester,
        );
        let good_proof =
            sign_test_jwt("oauth-client-attestation-pop+jwt", &proof_claims, &instance);

        let assert_error = |attestation: &str,
                            proof: &str,
                            options: &ClientAttestationVerificationOptions,
                            expected| {
            assert_eq!(
                verify_client_attestation(attestation, proof, options)
                    .unwrap_err()
                    .code(),
                expected,
            );
        };

        let wrong_attestation_signature =
            sign_test_jwt("oauth-client-attestation+jwt", &attestation_claims, &other);
        assert_error(
            &wrong_attestation_signature,
            &good_proof,
            &options,
            CoreErrorCode::InvalidSignature,
        );
        let wrong_proof_signature =
            sign_test_jwt("oauth-client-attestation-pop+jwt", &proof_claims, &other);
        assert_error(
            &good_attestation,
            &wrong_proof_signature,
            &options,
            CoreErrorCode::InvalidSignature,
        );

        let bad_attestation_typ = sign_test_jwt("JWT", &attestation_claims, &attester);
        assert_error(
            &bad_attestation_typ,
            &good_proof,
            &options,
            CoreErrorCode::InvalidInput,
        );
        let bad_proof_typ = sign_test_jwt("JWT", &proof_claims, &instance);
        assert_error(
            &good_attestation,
            &bad_proof_typ,
            &options,
            CoreErrorCode::InvalidInput,
        );

        let critical_attestation = sign_test_jwt_with_header(
            &json!({
                "alg": "ES256",
                "typ": "oauth-client-attestation+jwt",
                "kid": attester.key_id.as_str(),
                "crit": ["unsupported-extension"],
                "unsupported-extension": true,
            }),
            &attestation_claims,
            &attester,
        );
        assert_error(
            &critical_attestation,
            &good_proof,
            &options,
            CoreErrorCode::UnsupportedAlgorithm,
        );
        let critical_proof = sign_test_jwt_with_header(
            &json!({
                "alg": "ES256",
                "typ": "oauth-client-attestation-pop+jwt",
                "kid": instance.key_id.as_str(),
                "crit": ["unsupported-extension"],
                "unsupported-extension": true,
            }),
            &proof_claims,
            &instance,
        );
        assert_error(
            &good_attestation,
            &critical_proof,
            &options,
            CoreErrorCode::UnsupportedAlgorithm,
        );

        let mut no_subject = attestation_claims.clone();
        no_subject.as_object_mut().unwrap().remove("sub");
        let no_subject = sign_test_jwt("oauth-client-attestation+jwt", &no_subject, &attester);
        assert_error(
            &no_subject,
            &good_proof,
            &options,
            CoreErrorCode::InvalidInput,
        );
        let wrong_client = ClientAttestationVerificationOptions {
            expected_client_id: Some("different-client".to_owned()),
            ..options.clone()
        };
        assert_error(
            &good_attestation,
            &good_proof,
            &wrong_client,
            CoreErrorCode::BindingCheckFailed,
        );

        let mut expired_attestation = attestation_claims.clone();
        expired_attestation["exp"] = json!(now - 1);
        let expired_attestation = sign_test_jwt(
            "oauth-client-attestation+jwt",
            &expired_attestation,
            &attester,
        );
        assert_error(
            &expired_attestation,
            &good_proof,
            &options,
            CoreErrorCode::FreshnessCheckFailed,
        );
        let mut future_proof = proof_claims.clone();
        future_proof["iat"] = json!(now + DEFAULT_MAX_KB_FUTURE_SKEW_SECONDS + 1);
        future_proof["nbf"] = future_proof["iat"].clone();
        future_proof["exp"] = json!(now + 300);
        let future_proof =
            sign_test_jwt("oauth-client-attestation-pop+jwt", &future_proof, &instance);
        assert_error(
            &good_attestation,
            &future_proof,
            &options,
            CoreErrorCode::FreshnessCheckFailed,
        );

        let mut empty_jti = proof_claims.clone();
        empty_jti["jti"] = json!("");
        let empty_jti = sign_test_jwt("oauth-client-attestation-pop+jwt", &empty_jti, &instance);
        assert_error(
            &good_attestation,
            &empty_jti,
            &options,
            CoreErrorCode::InvalidInput,
        );
        let mut wrong_issuer = proof_claims.clone();
        wrong_issuer["iss"] = json!("different-client");
        let wrong_issuer =
            sign_test_jwt("oauth-client-attestation-pop+jwt", &wrong_issuer, &instance);
        assert_error(
            &good_attestation,
            &wrong_issuer,
            &options,
            CoreErrorCode::BindingCheckFailed,
        );
        let wrong_challenge = ClientAttestationVerificationOptions {
            expected_challenge: Some("different-challenge".to_owned()),
            ..options.clone()
        };
        assert_error(
            &good_attestation,
            &good_proof,
            &wrong_challenge,
            CoreErrorCode::BindingCheckFailed,
        );

        let invalid_options = ClientAttestationVerificationOptions {
            max_age_seconds: 0,
            ..options
        };
        assert_error(
            &good_attestation,
            &good_proof,
            &invalid_options,
            CoreErrorCode::InvalidInput,
        );
    }

    #[test]
    fn creates_deterministic_non_root_x509_public_material_for_test_issuer() {
        let first = deterministic_test_x509_identity("issuer-key", "issuer:0").unwrap();
        let second = deterministic_test_x509_identity("issuer-key", "issuer:0").unwrap();

        assert_eq!(first, second);
        assert_eq!(first.x5c.len(), 1);
        assert!(Base64::decode_vec(&first.x5c[0]).unwrap().len() > 100);
        assert!(
            first
                .trust_anchor_pem
                .starts_with("-----BEGIN CERTIFICATE-----")
        );
        assert_eq!(first.public_jwk.kid.as_deref(), Some("issuer-key"));
    }

    #[test]
    fn oid4vci_credential_response_jwe_round_trips_with_compression() {
        let recipient = p256::SecretKey::from_slice(&TEST_HOLDER_PRIVATE_SCALAR).unwrap();
        let ephemeral = p256::SecretKey::from_slice(&TEST_PRIVATE_SCALAR).unwrap();
        let recipient_jwk = JwePublicJwk::from_public_key(
            recipient.public_key(),
            Some("wallet-encryption-key".to_owned()),
            Some("ECDH-ES".to_owned()),
        );
        let parameters = Oid4vciCredentialResponseEncryption {
            jwk: recipient_jwk,
            enc: "A256GCM".to_owned(),
            zip: Some("DEF".to_owned()),
        };
        let plaintext = json!({"credentials":[{"credential":"synthetic-credential"}]});

        let encrypted = encrypt_oid4vci_credential_response_with_material(
            &plaintext,
            &parameters,
            &ephemeral,
            &[7_u8; 12],
        )
        .unwrap();
        let decrypted =
            decrypt_oid4vci_jwe(&encrypted, &recipient, Some("wallet-encryption-key")).unwrap();

        assert_eq!(decrypted, plaintext);
        assert_eq!(encrypted.split('.').count(), 5);
        assert!(!encrypted.contains("synthetic-credential"));
    }

    #[test]
    fn oid4vci_request_jwe_rejects_wrong_key_algorithm_and_tampering() {
        let recipient = p256::SecretKey::from_slice(&TEST_HOLDER_PRIVATE_SCALAR).unwrap();
        let ephemeral = p256::SecretKey::from_slice(&TEST_PRIVATE_SCALAR).unwrap();
        let mut parameters = Oid4vciCredentialResponseEncryption {
            jwk: JwePublicJwk::from_public_key(
                recipient.public_key(),
                Some("issuer-encryption-key".to_owned()),
                Some("RSA-OAEP".to_owned()),
            ),
            enc: "A256GCM".to_owned(),
            zip: None,
        };

        assert_eq!(
            encrypt_oid4vci_credential_response_with_material(
                &json!({"credential_configuration_id":"StudentCredential"}),
                &parameters,
                &ephemeral,
                &[3_u8; 12],
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::UnsupportedAlgorithm,
        );

        parameters.jwk.alg = Some("ECDH-ES".to_owned());
        parameters.jwk.x = b64_encode(&[0_u8; 32]);
        parameters.jwk.y = b64_encode(&[0_u8; 32]);
        assert_eq!(
            validate_oid4vci_credential_response_encryption(&parameters)
                .unwrap_err()
                .code(),
            CoreErrorCode::InvalidKey,
        );
        parameters.jwk = JwePublicJwk::from_public_key(
            recipient.public_key(),
            Some("issuer-encryption-key".to_owned()),
            Some("ECDH-ES".to_owned()),
        );
        let encrypted = encrypt_oid4vci_credential_response_with_material(
            &json!({"credential_configuration_id":"StudentCredential"}),
            &parameters,
            &ephemeral,
            &[3_u8; 12],
        )
        .unwrap();
        assert_eq!(
            decrypt_oid4vci_jwe(&encrypted, &recipient, Some("different-key"))
                .unwrap_err()
                .code(),
            CoreErrorCode::InvalidKey,
        );

        let mut critical_parts = encrypted.split('.').map(str::to_owned).collect::<Vec<_>>();
        let mut critical_header: Value =
            serde_json::from_slice(&b64_decode(&critical_parts[0]).unwrap()).unwrap();
        critical_header["crit"] = json!(["exp"]);
        critical_header["exp"] = json!(true);
        critical_parts[0] = b64_encode(&serde_json::to_vec(&critical_header).unwrap());
        assert_eq!(
            decrypt_oid4vci_jwe(
                &critical_parts.join("."),
                &recipient,
                Some("issuer-encryption-key"),
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::UnsupportedAlgorithm,
        );

        let mut parts = encrypted.split('.').map(str::to_owned).collect::<Vec<_>>();
        let last = parts[3].pop().unwrap();
        parts[3].push(if last == 'A' { 'B' } else { 'A' });
        assert_eq!(
            decrypt_oid4vci_jwe(&parts.join("."), &recipient, Some("issuer-encryption-key"))
                .unwrap_err()
                .code(),
            CoreErrorCode::VerificationFailed,
        );
    }

    #[test]
    fn ecdh_es_concat_kdf_matches_rfc7518_appendix_c() {
        let shared_secret = [
            158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49,
            110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
        ];

        let derived = ecdh_es_concat_kdf_bits(
            &shared_secret,
            "A128GCM",
            Some("QWxpY2U"),
            Some("Qm9i"),
            128,
        )
        .unwrap();

        assert_eq!(b64_encode(&derived), "VqqN6vgjbSBcIijNcacQGg");
    }

    #[test]
    fn oid4vp_jwe_accepts_an_authenticated_header_without_optional_cty() {
        let header = serde_json::from_value::<Oid4vpJweHeader>(json!({
            "alg": "ECDH-ES",
            "enc": "A256GCM",
            "kid": "ceremony-key",
            "epk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "GSb2vFYfIILrXZg2FXyNJVkDhvCu0lnpQWVUDtFRl1U",
                "y": "6Usx6Ni1wL5nuw7hqmWKfJ5AopQxZz02QlhfUOpw8AM"
            }
        }))
        .expect("cty is optional in a standards-valid direct_post.jwt header");

        validate_oid4vp_jwe_header(&header, "ceremony-key").unwrap();
    }

    #[test]
    fn oid4vci_encryption_parameters_reject_private_jwk_members() {
        let recipient = p256::SecretKey::from_slice(&TEST_HOLDER_PRIVATE_SCALAR).unwrap();
        let public = JwePublicJwk::from_public_key(
            recipient.public_key(),
            Some("recipient".to_owned()),
            Some("ECDH-ES".to_owned()),
        );
        let mut value = serde_json::to_value(Oid4vciCredentialResponseEncryption {
            jwk: public,
            enc: "A256GCM".to_owned(),
            zip: None,
        })
        .unwrap();
        value["jwk"]["d"] = json!("private-material");

        assert!(
            serde_json::from_value::<Oid4vciCredentialResponseEncryption>(value).is_err(),
            "private JWK members must not cross into the core",
        );
    }

    #[test]
    fn sha256_digest_matches_known_vector() {
        assert_eq!(
            sha256_b64url(b"abc"),
            "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
        );
    }

    #[test]
    fn verifies_attachment_bytes_against_disclosed_hash() {
        let expected = sha256_b64url(b"mock university photo bytes");

        verify_attachment(b"mock university photo bytes", &expected).unwrap();
        assert_eq!(
            verify_attachment(b"different photo bytes", &expected)
                .unwrap_err()
                .code(),
            CoreErrorCode::AttachmentCheckFailed
        );
    }

    #[test]
    fn did_web_resolution_urls_cover_root_port_and_path_forms() {
        assert_eq!(
            did_web_to_https_url("did:web:issuer.unsw.example.edu.au").unwrap(),
            "https://issuer.unsw.example.edu.au/.well-known/did.json"
        );
        assert_eq!(
            did_web_to_https_url("did:web:issuer.unsw.example.edu.au%3A8443").unwrap(),
            "https://issuer.unsw.example.edu.au:8443/.well-known/did.json"
        );
        assert_eq!(
            did_web_to_https_url("did:web:example.edu.au:issuers:student").unwrap(),
            "https://example.edu.au/issuers/student/did.json"
        );
    }

    #[test]
    fn did_web_document_builder_covers_all_five_planned_issuers() {
        let signer = TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, "issuer-1").unwrap();
        let identities = planned_issuer_did_web_identities("example.edu.au").unwrap();

        assert_eq!(
            identities
                .iter()
                .map(|identity| identity.did.as_str())
                .collect::<Vec<_>>(),
            [
                "did:web:issuer.unsw.example.edu.au",
                "did:web:hr.unsw.example.edu.au",
                "did:web:exams.unsw.example.edu.au",
                "did:web:home-affairs.gov.example.edu.au",
                "did:web:identity.gov.example.edu.au",
            ]
        );

        for identity in identities {
            let document =
                build_did_web_document(&identity.did, std::slice::from_ref(&signer.public_jwk))
                    .unwrap();
            let document_json = serde_json::to_value(&document).unwrap();

            assert_eq!(document.id, identity.did);
            assert_eq!(document.context, vec![DID_CONTEXT.to_owned()]);
            assert_eq!(
                document.verification_method[0].id,
                format!("{}#issuer-1", identity.did)
            );
            assert_eq!(document.verification_method[0].public_key_jwk.kty, "EC");
            assert_eq!(
                did_web_to_https_url(&identity.did).unwrap(),
                format!("https://{}/.well-known/did.json", identity.host)
            );
            assert_eq!(document_json["@context"], json!([DID_CONTEXT]));
            assert_eq!(document_json["verificationMethod"][0]["type"], "JsonWebKey");
        }
    }

    #[test]
    fn did_web_issuer_sd_jwt_presentation_verifies_via_document_resolution() {
        let did = "did:web:issuer.unsw.example.edu.au";
        let issuer_key_id = format!("{did}#issuer-1");
        let issuer =
            TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, issuer_key_id.clone())
                .unwrap();
        let holder =
            TestP256Signer::from_private_scalar(&TEST_HOLDER_PRIVATE_SCALAR, "holder-1").unwrap();
        let mut payload = student_vector_payload(&holder.public_jwk);
        payload["iss"] = json!(did);
        payload["issuer"] = json!(did);
        let header = JwsHeader::es256(Some(VC_SD_JWT_TYP.to_owned()), Some(issuer_key_id));
        let mut salts = FixedSaltSource::new((0_u8..8).map(|index| vec![index; 16]));
        let issued = issue_sd_jwt(
            payload,
            &student_disclosure_specs(),
            0,
            &header,
            &issuer,
            &issuer.key_id,
            &mut salts,
        )
        .unwrap();
        let presentation = present_sd_jwt(
            &issued.compact,
            &DisclosureProfile::uc3_study_space(),
            &holder,
            &holder.key_id,
            "https://study-space.example/oid4vp",
            "nonce-123",
            1783000100,
        )
        .unwrap();
        let document =
            build_did_web_document(did, std::slice::from_ref(&issuer.public_jwk)).unwrap();
        let resolver = FixedResolver {
            url: did_web_to_https_url(did).unwrap(),
            body: serde_json::to_vec(&document).unwrap(),
        };

        let verified = verify_sd_jwt_presentation_with_did_web(
            &presentation.presentation,
            &resolver,
            &SdJwtVerificationOptions::for_profile(
                "https://study-space.example/oid4vp",
                "nonce-123",
                1783000110,
                &DisclosureProfile::uc3_study_space(),
            ),
        )
        .unwrap();

        assert_eq!(verified.processed_payload["iss"], did);
        assert_eq!(
            verified.processed_payload["credentialSubject"]["enrolled"],
            json!(true)
        );
    }

    #[test]
    fn oid4vp_final_request_object_verifies_via_client_id_did() {
        let verifier_did = "did:web:study-space.example";
        let verifier_key_id = format!("{verifier_did}#request-1");
        let verifier =
            TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, verifier_key_id.clone())
                .unwrap();
        let header = JwsHeader::es256(
            Some("oauth-authz-req+jwt".to_owned()),
            Some(verifier_key_id),
        );
        let compact = sign_compact_jws_json(
            &header,
            &oid4vp_request_payload(verifier_did),
            &verifier,
            &verifier.key_id,
        )
        .unwrap();
        let document =
            build_did_web_document(verifier_did, std::slice::from_ref(&verifier.public_jwk))
                .unwrap();
        let resolver = FixedResolver {
            url: did_web_to_https_url(verifier_did).unwrap(),
            body: serde_json::to_vec(&document).unwrap(),
        };

        let verified = verify_oid4vp_request_object(&compact, &resolver, 1_783_000_100).unwrap();

        assert_eq!(verified.verifier_did, verifier_did);
        assert_eq!(
            verified.payload["client_id"],
            json!(format!("decentralized_identifier:{verifier_did}"))
        );
        assert_eq!(verified.payload["response_mode"], json!("direct_post"));
    }

    #[test]
    fn oidf_wallet_request_profiles_validate_before_disclosure() {
        let verifier =
            TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, "oidf-verifier").unwrap();
        let final_client_id = "decentralized_identifier:did:jwk:eyJjcnYiOiJQLTI1NiJ9";
        let final_header = JwsHeader::es256(Some(OID4VP_REQUEST_TYP.to_owned()), None);
        let final_request = sign_compact_jws_json(
            &final_header,
            &oidf_wallet_payload(final_client_id, Oid4vpWalletInteropProfile::Final),
            &verifier,
            &verifier.key_id,
        )
        .unwrap();
        let final_verified = verify_oid4vp_wallet_interop_request(
            &final_request,
            &verifier.public_jwk,
            &Oid4vpWalletRequestPolicy {
                profile: Oid4vpWalletInteropProfile::Final,
                activation_client_id: final_client_id.to_owned(),
                expected_client_id: final_client_id.to_owned(),
                request_uri: concat!(
                    "https://localhost.emobix.co.uk:8443/test/a/plan/requesturi/",
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                )
                .to_owned(),
                expected_origin: "https://localhost.emobix.co.uk:8443".to_owned(),
                expected_x5c: None,
                available_claims: oidf_wallet_available_claims(),
                trusted_authority_key_identifiers: Vec::new(),
            },
        )
        .unwrap();
        assert_eq!(
            final_verified.credential_selections[0].requested_claims,
            ["given_name", "family_name"]
        );
        assert!(final_verified.dcql_satisfied);
        assert!(final_verified.encryption_key.is_none());

        let leaf = Base64::encode_string(b"synthetic public certificate bytes");
        let haip_client_id = format!(
            "x509_hash:{}",
            sha256_b64url(b"synthetic public certificate bytes")
        );
        let mut haip_header = JwsHeader::es256(Some(OID4VP_REQUEST_TYP.to_owned()), None);
        haip_header.x5c = Some(vec![leaf.clone()]);
        let haip_request = sign_compact_jws_json(
            &haip_header,
            &oidf_wallet_payload(&haip_client_id, Oid4vpWalletInteropProfile::Haip),
            &verifier,
            &verifier.key_id,
        )
        .unwrap();
        let haip_verified = verify_oid4vp_wallet_interop_request(
            &haip_request,
            &verifier.public_jwk,
            &Oid4vpWalletRequestPolicy {
                profile: Oid4vpWalletInteropProfile::Haip,
                activation_client_id: haip_client_id.clone(),
                expected_client_id: haip_client_id,
                request_uri: concat!(
                    "https://localhost.emobix.co.uk:8443/test/a/plan/requesturi/",
                    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
                )
                .to_owned(),
                expected_origin: "https://localhost.emobix.co.uk:8443".to_owned(),
                expected_x5c: Some(vec![leaf]),
                available_claims: oidf_wallet_available_claims(),
                trusted_authority_key_identifiers: Vec::new(),
            },
        )
        .unwrap();
        assert!(haip_verified.encryption_key.is_some());
    }

    #[test]
    fn oidf_wallet_presentation_requires_an_explicit_ietf_format() {
        let issuer =
            TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, "oidf-issuer").unwrap();
        let holder = TestP256Signer::from_private_scalar(
            &TEST_HOLDER_PRIVATE_SCALAR,
            "oidf-holder-private-handle",
        )
        .unwrap();
        let payload = json!({
            "iss": "https://issuer.example",
            "iat": 1_788_000_000,
            "exp": 1_788_003_600,
            "vct": "urn:eudi:pid:1",
            "cnf": {"jwk": holder.public_jwk.clone()},
            "given_name": "OIDF"
        });
        let mut salts = FixedSaltSource::new([vec![42; 16]]);
        let credential = issue_sd_jwt_with_format(
            payload,
            &[DisclosureSpec::new(Vec::<String>::new(), "given_name")],
            &JwsHeader::es256(Some(DC_SD_JWT_TYP.to_owned()), None),
            &issuer,
            &issuer.key_id,
            &mut salts,
            SdJwtIssueOptions {
                decoy_digests: 0,
                format: CredentialFormat::IetfSdJwtVc,
            },
        )
        .unwrap();

        let named_only = present_sd_jwt(
            &credential.compact,
            &DisclosureProfile::new("oidf_wallet_presentation", [["given_name"]]),
            &holder,
            &holder.key_id,
            "decentralized_identifier:did:jwk:public",
            "oidf-wallet-nonce-123456",
            1_788_000_100,
        )
        .unwrap();
        let named_only_header: JwsHeader =
            decode_json_segment(named_only.kb_jwt.split('.').next().unwrap()).unwrap();
        assert_eq!(named_only_header.typ.as_deref(), Some(KB_JWT_TYP));
        assert_eq!(
            named_only_header.kid.as_deref(),
            Some(holder.key_id.as_str()),
            "a disclosure-profile name must not select IETF header semantics",
        );

        let interop = present_sd_jwt(
            &credential.compact,
            &DisclosureProfile::new("any_profile_name", [["given_name"]])
                .with_credential_format(CredentialFormat::IetfSdJwtVc),
            &holder,
            &holder.key_id,
            "decentralized_identifier:did:jwk:public",
            "oidf-wallet-nonce-123456",
            1_788_000_100,
        )
        .unwrap();
        let interop_header: JwsHeader =
            decode_json_segment(interop.kb_jwt.split('.').next().unwrap()).unwrap();
        assert_eq!(interop_header.typ.as_deref(), Some(KB_JWT_TYP));
        assert!(interop_header.kid.is_none());

        assert_eq!(
            present_sd_jwt(
                &credential.compact,
                &DisclosureProfile::new("wrong_format", [["given_name"]])
                    .with_credential_format(CredentialFormat::W3cVcDataModel),
                &holder,
                &holder.key_id,
                "https://verifier.example",
                "normal-wallet-nonce-123456",
                1_788_000_100,
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::InvalidInput
        );

        let normal = present_sd_jwt(
            &credential.compact,
            &DisclosureProfile::new("normal_profile", [["given_name"]]),
            &holder,
            &holder.key_id,
            "https://verifier.example",
            "normal-wallet-nonce-123456",
            1_788_000_100,
        )
        .unwrap();
        let normal_header: JwsHeader =
            decode_json_segment(normal.kb_jwt.split('.').next().unwrap()).unwrap();
        assert_eq!(normal_header.kid.as_deref(), Some(holder.key_id.as_str()));
    }

    #[test]
    fn oidf_wallet_request_refuses_identity_dcql_and_encryption_failures() {
        let verifier =
            TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, "oidf-verifier").unwrap();
        let client_id = "decentralized_identifier:did:jwk:eyJjcnYiOiJQLTI1NiJ9";
        let policy = Oid4vpWalletRequestPolicy {
            profile: Oid4vpWalletInteropProfile::Final,
            activation_client_id: client_id.to_owned(),
            expected_client_id: client_id.to_owned(),
            request_uri: concat!(
                "https://localhost.emobix.co.uk:8443/test/a/plan/requesturi/",
                "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
            )
            .to_owned(),
            expected_origin: "https://localhost.emobix.co.uk:8443".to_owned(),
            expected_x5c: None,
            available_claims: oidf_wallet_available_claims(),
            trusted_authority_key_identifiers: Vec::new(),
        };
        let header = JwsHeader::es256(Some(OID4VP_REQUEST_TYP.to_owned()), None);
        let signed = |payload: &Value| {
            sign_compact_jws_json(&header, payload, &verifier, &verifier.key_id).unwrap()
        };

        let attacker =
            TestP256Signer::from_private_scalar(&TEST_HOLDER_PRIVATE_SCALAR, "attacker").unwrap();
        let forged = sign_compact_jws_json(
            &header,
            &oidf_wallet_payload(client_id, Oid4vpWalletInteropProfile::Final),
            &attacker,
            &attacker.key_id,
        )
        .unwrap();
        assert_eq!(
            verify_oid4vp_wallet_interop_request(&forged, &verifier.public_jwk, &policy)
                .unwrap_err()
                .code(),
            CoreErrorCode::InvalidSignature
        );

        let mut unbound_policy = policy.clone();
        unbound_policy.request_uri =
            "https://attacker.example/test/a/plan/requesturi/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                .to_owned();
        assert_eq!(
            verify_oid4vp_wallet_interop_request(
                &signed(&oidf_wallet_payload(
                    client_id,
                    Oid4vpWalletInteropProfile::Final
                )),
                &verifier.public_jwk,
                &unbound_policy
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::VerificationFailed
        );

        let mut mismatched = oidf_wallet_payload(client_id, Oid4vpWalletInteropProfile::Final);
        mismatched["client_id"] = json!("invalid_scheme:attacker");
        assert_eq!(
            verify_oid4vp_wallet_interop_request(
                &signed(&mismatched),
                &verifier.public_jwk,
                &policy
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::TrustCheckFailed
        );

        let mut broad = oidf_wallet_payload(client_id, Oid4vpWalletInteropProfile::Final);
        broad["dcql_query"]["credentials"][0]["claims"] = json!([{"path": ["birth_date"]}]);
        assert_eq!(
            verify_oid4vp_wallet_interop_request(&signed(&broad), &verifier.public_jwk, &policy)
                .unwrap_err()
                .code(),
            CoreErrorCode::MissingDisclosure
        );

        let mut no_audience = oidf_wallet_payload(client_id, Oid4vpWalletInteropProfile::Final);
        no_audience.as_object_mut().unwrap().remove("aud");
        assert_eq!(
            verify_oid4vp_wallet_interop_request(
                &signed(&no_audience),
                &verifier.public_jwk,
                &policy
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::VerificationFailed
        );

        let mut no_nonce = oidf_wallet_payload(client_id, Oid4vpWalletInteropProfile::Final);
        no_nonce.as_object_mut().unwrap().remove("nonce");
        assert_eq!(
            verify_oid4vp_wallet_interop_request(&signed(&no_nonce), &verifier.public_jwk, &policy)
                .unwrap_err()
                .code(),
            CoreErrorCode::VerificationFailed
        );

        let mut bad_metadata = oidf_wallet_payload(client_id, Oid4vpWalletInteropProfile::Final);
        bad_metadata["client_metadata"]["vp_formats_supported"] = json!({});
        assert_eq!(
            verify_oid4vp_wallet_interop_request(
                &signed(&bad_metadata),
                &verifier.public_jwk,
                &policy
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::VerificationFailed
        );

        let mut malformed_dcql = oidf_wallet_payload(client_id, Oid4vpWalletInteropProfile::Final);
        malformed_dcql["dcql_query"]["credentials"] = json!("invalid");
        assert_eq!(
            verify_oid4vp_wallet_interop_request(
                &signed(&malformed_dcql),
                &verifier.public_jwk,
                &policy
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::VerificationFailed
        );

        let mut bad_response = oidf_wallet_payload(client_id, Oid4vpWalletInteropProfile::Final);
        bad_response["response_uri"] =
            json!("https://localhost.emobix.co.uk:8443/test/a/plan/responseuri/bad");
        assert_eq!(
            verify_oid4vp_wallet_interop_request(
                &signed(&bad_response),
                &verifier.public_jwk,
                &policy
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::VerificationFailed
        );

        let mut transaction = oidf_wallet_payload(client_id, Oid4vpWalletInteropProfile::Final);
        transaction["transaction_data"] = json!(["opaque"]);
        assert_eq!(
            verify_oid4vp_wallet_interop_request(
                &signed(&transaction),
                &verifier.public_jwk,
                &policy
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::VerificationFailed
        );

        let leaf = Base64::encode_string(b"synthetic public certificate bytes");
        let haip_client_id = format!(
            "x509_hash:{}",
            sha256_b64url(b"synthetic public certificate bytes")
        );
        let mut haip_header = JwsHeader::es256(Some(OID4VP_REQUEST_TYP.to_owned()), None);
        haip_header.x5c = Some(vec![leaf.clone()]);
        let haip_signed = |payload: &Value| {
            sign_compact_jws_json(&haip_header, payload, &verifier, &verifier.key_id).unwrap()
        };
        let haip_policy = Oid4vpWalletRequestPolicy {
            profile: Oid4vpWalletInteropProfile::Haip,
            activation_client_id: haip_client_id.clone(),
            expected_client_id: haip_client_id.clone(),
            request_uri: concat!(
                "https://localhost.emobix.co.uk:8443/test/a/plan/requesturi/",
                "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
            )
            .to_owned(),
            expected_origin: "https://localhost.emobix.co.uk:8443".to_owned(),
            expected_x5c: Some(vec![leaf]),
            available_claims: oidf_wallet_available_claims(),
            trusted_authority_key_identifiers: Vec::new(),
        };
        let mut no_encryption =
            oidf_wallet_payload(&haip_client_id, Oid4vpWalletInteropProfile::Haip);
        no_encryption["client_metadata"]["jwks"] = json!({"keys": []});
        assert_eq!(
            verify_oid4vp_wallet_interop_request(
                &haip_signed(&no_encryption),
                &verifier.public_jwk,
                &haip_policy
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::InvalidKey
        );

        let mut untrusted_header = haip_header.clone();
        untrusted_header.x5c = Some(vec![Base64::encode_string(b"other certificate")]);
        let untrusted = sign_compact_jws_json(
            &untrusted_header,
            &oidf_wallet_payload(&haip_client_id, Oid4vpWalletInteropProfile::Haip),
            &verifier,
            &verifier.key_id,
        )
        .unwrap();
        assert_eq!(
            verify_oid4vp_wallet_interop_request(&untrusted, &verifier.public_jwk, &haip_policy)
                .unwrap_err()
                .code(),
            CoreErrorCode::TrustCheckFailed
        );

        let mut extended_header = haip_header;
        extended_header.x5c = Some(vec![
            haip_policy.expected_x5c.clone().unwrap()[0].clone(),
            Base64::encode_string(b"unvalidated intermediate certificate"),
        ]);
        let extended = sign_compact_jws_json(
            &extended_header,
            &oidf_wallet_payload(&haip_client_id, Oid4vpWalletInteropProfile::Haip),
            &verifier,
            &verifier.key_id,
        )
        .unwrap();
        assert_eq!(
            verify_oid4vp_wallet_interop_request(&extended, &verifier.public_jwk, &haip_policy)
                .unwrap_err()
                .code(),
            CoreErrorCode::TrustCheckFailed
        );
    }

    #[test]
    fn oidf_wallet_dcql_selects_one_satisfiable_claim_set_and_refuses_constraints() {
        let verifier =
            TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, "oidf-verifier").unwrap();
        let client_id = "decentralized_identifier:did:jwk:eyJjcnYiOiJQLTI1NiJ9";
        let policy = Oid4vpWalletRequestPolicy {
            profile: Oid4vpWalletInteropProfile::Final,
            activation_client_id: client_id.to_owned(),
            expected_client_id: client_id.to_owned(),
            request_uri: concat!(
                "https://localhost.emobix.co.uk:8443/test/a/plan/requesturi/",
                "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
            )
            .to_owned(),
            expected_origin: "https://localhost.emobix.co.uk:8443".to_owned(),
            expected_x5c: None,
            available_claims: oidf_wallet_available_claims(),
            trusted_authority_key_identifiers: Vec::new(),
        };
        let header = JwsHeader::es256(Some(OID4VP_REQUEST_TYP.to_owned()), None);
        let signed = |payload: &Value| {
            sign_compact_jws_json(&header, payload, &verifier, &verifier.key_id).unwrap()
        };

        let mut alternatives = oidf_wallet_payload(client_id, Oid4vpWalletInteropProfile::Final);
        alternatives["dcql_query"]["credentials"][0]["claims"] = json!([
            {"id": "preferred", "path": ["given_name"]},
            {"id": "fallback", "path": ["family_name"]}
        ]);
        alternatives["dcql_query"]["credentials"][0]["claim_sets"] =
            json!([["preferred"], ["fallback"]]);
        let selected = verify_oid4vp_wallet_interop_request(
            &signed(&alternatives),
            &verifier.public_jwk,
            &policy,
        )
        .unwrap();
        assert_eq!(
            selected.credential_selections[0].requested_claims,
            ["given_name"]
        );

        let mut unreferenced = alternatives.clone();
        unreferenced["dcql_query"]["credentials"][0]["claim_sets"] = json!([["preferred"]]);
        let selected = verify_oid4vp_wallet_interop_request(
            &signed(&unreferenced),
            &verifier.public_jwk,
            &policy,
        )
        .unwrap();
        assert_eq!(
            selected.credential_selections[0].requested_claims,
            ["given_name"]
        );

        let mut duplicate_credentials =
            oidf_wallet_payload(client_id, Oid4vpWalletInteropProfile::Final);
        let mut second = duplicate_credentials["dcql_query"]["credentials"][0].clone();
        duplicate_credentials["dcql_query"]["credentials"][0]["id"] =
            json!("nonexistent_credential");
        second["id"] = json!("nonexistent_credential");
        duplicate_credentials["dcql_query"]["credentials"] = json!([
            duplicate_credentials["dcql_query"]["credentials"][0].clone(),
            second
        ]);
        duplicate_credentials["dcql_query"]["credential_sets"] = json!([
            {"options": [["nonexistent_credential"]], "required": true},
            {"options": [["nonexistent_credential"]], "required": false}
        ]);
        assert_eq!(
            verify_oid4vp_wallet_interop_request(
                &signed(&duplicate_credentials),
                &verifier.public_jwk,
                &policy,
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::VerificationFailed
        );

        let mut mismatched_value =
            oidf_wallet_payload(client_id, Oid4vpWalletInteropProfile::Final);
        mismatched_value["dcql_query"]["credentials"][0]["claims"] =
            json!([{"path": ["given_name"], "values": ["not-the-held-value"]}]);
        let value_result = verify_oid4vp_wallet_interop_request(
            &signed(&mismatched_value),
            &verifier.public_jwk,
            &policy,
        )
        .unwrap();
        assert!(!value_result.dcql_satisfied);
        assert!(value_result.credential_selections.is_empty());

        let mut untrusted_authority =
            oidf_wallet_payload(client_id, Oid4vpWalletInteropProfile::Final);
        untrusted_authority["dcql_query"]["credentials"][0]["trusted_authorities"] =
            json!([{"type": "aki", "values": ["untrusted-authority"]}]);
        let authority_result = verify_oid4vp_wallet_interop_request(
            &signed(&untrusted_authority),
            &verifier.public_jwk,
            &policy,
        )
        .unwrap();
        assert!(!authority_result.dcql_satisfied);
        assert!(authority_result.credential_selections.is_empty());

        let mut unknown_members = oidf_wallet_payload(client_id, Oid4vpWalletInteropProfile::Final);
        unknown_members["dcql_query"]["future_query_member"] = json!(true);
        unknown_members["dcql_query"]["credentials"][0]["future_credential_member"] = json!(true);
        unknown_members["dcql_query"]["credentials"][0]["meta"]["future_meta_member"] = json!(true);
        unknown_members["dcql_query"]["credentials"][0]["claims"][0]["future_claim_member"] =
            json!(true);
        let accepted = verify_oid4vp_wallet_interop_request(
            &signed(&unknown_members),
            &verifier.public_jwk,
            &policy,
        );
        assert!(accepted.unwrap().dcql_satisfied);

        let mut trusted_policy = policy.clone();
        trusted_policy.trusted_authority_key_identifiers = vec!["trusted-authority".to_owned()];
        let mut unknown_authority_member =
            oidf_wallet_payload(client_id, Oid4vpWalletInteropProfile::Final);
        unknown_authority_member["dcql_query"]["credentials"][0]["trusted_authorities"] = json!([{
            "type": "aki",
            "values": ["trusted-authority"],
            "future_authority_member": true
        }]);
        assert!(
            verify_oid4vp_wallet_interop_request(
                &signed(&unknown_authority_member),
                &verifier.public_jwk,
                &trusted_policy,
            )
            .unwrap()
            .dcql_satisfied
        );

        for holder_binding in [json!(true), json!(false)] {
            let mut request = oidf_wallet_payload(client_id, Oid4vpWalletInteropProfile::Final);
            request["dcql_query"]["credentials"][0]["require_cryptographic_holder_binding"] =
                holder_binding;
            assert!(
                verify_oid4vp_wallet_interop_request(
                    &signed(&request),
                    &verifier.public_jwk,
                    &policy,
                )
                .unwrap()
                .dcql_satisfied
            );
        }
        let mut invalid_holder_binding =
            oidf_wallet_payload(client_id, Oid4vpWalletInteropProfile::Final);
        invalid_holder_binding["dcql_query"]["credentials"][0]["require_cryptographic_holder_binding"] =
            json!("false");
        assert_eq!(
            verify_oid4vp_wallet_interop_request(
                &signed(&invalid_holder_binding),
                &verifier.public_jwk,
                &policy,
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::VerificationFailed
        );

        for multiple in [json!(false), json!(true)] {
            let mut request = oidf_wallet_payload(client_id, Oid4vpWalletInteropProfile::Final);
            request["dcql_query"]["credentials"][0]["multiple"] = multiple;
            assert!(
                verify_oid4vp_wallet_interop_request(
                    &signed(&request),
                    &verifier.public_jwk,
                    &policy,
                )
                .unwrap()
                .dcql_satisfied
            );
        }
        let mut invalid_multiple =
            oidf_wallet_payload(client_id, Oid4vpWalletInteropProfile::Final);
        invalid_multiple["dcql_query"]["credentials"][0]["multiple"] = json!(1);
        assert_eq!(
            verify_oid4vp_wallet_interop_request(
                &signed(&invalid_multiple),
                &verifier.public_jwk,
                &policy,
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::VerificationFailed
        );

        let mut reordered = oidf_wallet_payload(client_id, Oid4vpWalletInteropProfile::Final);
        let held = reordered["dcql_query"]["credentials"][0].clone();
        let mut missing = held.clone();
        missing["id"] = json!("nonexistent_credential");
        missing["meta"]["vct_values"] = json!(["urn:eudi:pid:missing"]);
        reordered["dcql_query"]["credentials"] = json!([missing, held]);
        reordered["dcql_query"]["credential_sets"] = json!([
            {"options": [["nonexistent_credential"]], "required": false},
            {"options": [["my_credential"]], "future_set_member": true}
        ]);
        let reordered_result = verify_oid4vp_wallet_interop_request(
            &signed(&reordered),
            &verifier.public_jwk,
            &policy,
        )
        .unwrap();
        assert_eq!(
            reordered_result
                .credential_selections
                .iter()
                .map(|selection| selection.credential_id.as_str())
                .collect::<Vec<_>>(),
            ["my_credential"]
        );
        assert!(reordered_result.dcql_satisfied);

        let mut overlapping_sets =
            oidf_wallet_payload(client_id, Oid4vpWalletInteropProfile::Final);
        let mut alternate = overlapping_sets["dcql_query"]["credentials"][0].clone();
        alternate["id"] = json!("alternate_credential");
        overlapping_sets["dcql_query"]["credentials"]
            .as_array_mut()
            .unwrap()
            .push(alternate);
        overlapping_sets["dcql_query"]["credential_sets"] = json!([
            {"options": [["my_credential"], ["alternate_credential"]]},
            {"options": [["alternate_credential"], ["my_credential"]]}
        ]);
        let overlapping_result = verify_oid4vp_wallet_interop_request(
            &signed(&overlapping_sets),
            &verifier.public_jwk,
            &policy,
        )
        .unwrap();
        assert_eq!(
            overlapping_result
                .credential_selections
                .iter()
                .map(|selection| selection.credential_id.as_str())
                .collect::<Vec<_>>(),
            ["my_credential"]
        );

        let mut repeated_credential =
            oidf_wallet_payload(client_id, Oid4vpWalletInteropProfile::Final);
        repeated_credential["dcql_query"]["credentials"][0]["claims"] =
            json!([{"path": ["given_name"]}]);
        let mut family_query = repeated_credential["dcql_query"]["credentials"][0].clone();
        family_query["id"] = json!("family_query");
        family_query["claims"] = json!([{"path": ["family_name"]}]);
        repeated_credential["dcql_query"]["credentials"] = json!([
            repeated_credential["dcql_query"]["credentials"][0].clone(),
            family_query
        ]);
        let repeated_result = verify_oid4vp_wallet_interop_request(
            &signed(&repeated_credential),
            &verifier.public_jwk,
            &policy,
        )
        .unwrap();
        assert!(repeated_result.dcql_satisfied);
        assert_eq!(
            repeated_result
                .credential_selections
                .iter()
                .map(|selection| (
                    selection.credential_id.as_str(),
                    selection
                        .requested_claims
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                ))
                .collect::<Vec<_>>(),
            [
                ("my_credential", vec!["given_name"]),
                ("family_query", vec!["family_name"]),
            ]
        );

        let mut optional_only = oidf_wallet_payload(client_id, Oid4vpWalletInteropProfile::Final);
        let mut missing = optional_only["dcql_query"]["credentials"][0].clone();
        missing["id"] = json!("nonexistent_credential");
        missing["meta"]["vct_values"] = json!(["urn:eudi:pid:missing"]);
        optional_only["dcql_query"]["credentials"]
            .as_array_mut()
            .unwrap()
            .push(missing);
        optional_only["dcql_query"]["credential_sets"] = json!([
            {"options": [["nonexistent_credential"]], "required": false}
        ]);
        let optional_only_result = verify_oid4vp_wallet_interop_request(
            &signed(&optional_only),
            &verifier.public_jwk,
            &policy,
        )
        .unwrap();
        assert!(!optional_only_result.dcql_satisfied);
        assert!(optional_only_result.credential_selections.is_empty());
    }

    #[test]
    fn pinned_x509_identity_rejects_mismatched_key_anchor_and_root_in_chain() {
        let trusted = deterministic_test_x509_identity("trusted", "issuer:10").unwrap();
        let other = deterministic_test_x509_identity("other", "issuer:11").unwrap();
        let root_der = Base64::decode_vec(
            &trusted
                .trust_anchor_pem
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .collect::<String>(),
        )
        .unwrap();

        validate_pinned_x509_identity(
            &trusted.x5c,
            &trusted.trust_anchor_pem,
            &trusted.public_jwk,
            1_788_000_000,
        )
        .unwrap();
        assert_eq!(
            validate_pinned_x509_identity(
                &trusted.x5c,
                &trusted.trust_anchor_pem,
                &other.public_jwk,
                1_788_000_000,
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::TrustCheckFailed
        );
        let mut untrusted_root_der = root_der.clone();
        *untrusted_root_der.last_mut().unwrap() ^= 1;
        let untrusted_root = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            Base64::encode_string(&untrusted_root_der)
        );
        assert_eq!(
            validate_pinned_x509_identity(
                &trusted.x5c,
                &untrusted_root,
                &trusted.public_jwk,
                1_788_000_000,
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::TrustCheckFailed
        );

        let mut chain_with_root = trusted.x5c.clone();
        chain_with_root.push(Base64::encode_string(&root_der));
        assert_eq!(
            validate_pinned_x509_identity(
                &chain_with_root,
                &trusted.trust_anchor_pem,
                &trusted.public_jwk,
                1_788_000_000,
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::TrustCheckFailed
        );

        let with_intermediate = test_x509_identity_with_intermediate();
        let authority_key_identifiers = validate_pinned_x509_identity(
            &with_intermediate.x5c,
            &with_intermediate.trust_anchor_pem,
            &with_intermediate.public_jwk,
            1_788_000_000,
        )
        .unwrap();
        assert_eq!(authority_key_identifiers.len(), 2);

        for prohibited_path in [
            test_x509_identity_with_intermediate_options(
                BasicConstraints::Constrained(0),
                false,
                false,
            ),
            test_x509_identity_with_intermediate_options(
                BasicConstraints::Unconstrained,
                true,
                false,
            ),
        ] {
            assert_eq!(
                validate_pinned_x509_identity(
                    &prohibited_path.x5c,
                    &prohibited_path.trust_anchor_pem,
                    &prohibited_path.public_jwk,
                    1_788_000_000,
                )
                .unwrap_err()
                .code(),
                CoreErrorCode::TrustCheckFailed
            );
        }

        let self_issued_rollover = test_x509_identity_with_intermediate_options(
            BasicConstraints::Constrained(0),
            false,
            true,
        );
        validate_pinned_x509_identity(
            &self_issued_rollover.x5c,
            &self_issued_rollover.trust_anchor_pem,
            &self_issued_rollover.public_jwk,
            1_788_000_000,
        )
        .unwrap();
    }

    #[test]
    fn oid4vp_final_request_object_rejects_untrusted_or_stale_inputs() {
        let verifier_did = "did:web:study-space.example";
        let verifier_key_id = format!("{verifier_did}#request-1");
        let verifier =
            TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, verifier_key_id.clone())
                .unwrap();
        let other = TestP256Signer::from_private_scalar(
            &TEST_HOLDER_PRIVATE_SCALAR,
            verifier_key_id.clone(),
        )
        .unwrap();
        let document =
            build_did_web_document(verifier_did, std::slice::from_ref(&verifier.public_jwk))
                .unwrap();
        let resolver = FixedResolver {
            url: did_web_to_https_url(verifier_did).unwrap(),
            body: serde_json::to_vec(&document).unwrap(),
        };
        let signed = |header: JwsHeader, payload: Value, signer: &TestP256Signer| {
            sign_compact_jws_json(&header, &payload, signer, &signer.key_id).unwrap()
        };
        let correct_header = JwsHeader::es256(
            Some("oauth-authz-req+jwt".to_owned()),
            Some(verifier_key_id),
        );

        let missing_kid = signed(
            JwsHeader::es256(Some("oauth-authz-req+jwt".to_owned()), None),
            oid4vp_request_payload(verifier_did),
            &verifier,
        );
        assert_eq!(
            verify_oid4vp_request_object(&missing_kid, &resolver, 1_783_000_100)
                .unwrap_err()
                .code(),
            CoreErrorCode::KeyNotFound
        );

        let unsigned = serde_json::to_string(&oid4vp_request_payload(verifier_did)).unwrap();
        assert_eq!(
            verify_oid4vp_request_object(&unsigned, &resolver, 1_783_000_100)
                .unwrap_err()
                .code(),
            CoreErrorCode::MalformedJws
        );

        let bad_signature = signed(
            correct_header.clone(),
            oid4vp_request_payload(verifier_did),
            &other,
        );
        assert_eq!(
            verify_oid4vp_request_object(&bad_signature, &resolver, 1_783_000_100)
                .unwrap_err()
                .code(),
            CoreErrorCode::InvalidSignature
        );

        let bad_typ = signed(
            JwsHeader::es256(Some("JWT".to_owned()), correct_header.kid.clone()),
            oid4vp_request_payload(verifier_did),
            &verifier,
        );
        assert_eq!(
            verify_oid4vp_request_object(&bad_typ, &resolver, 1_783_000_100)
                .unwrap_err()
                .code(),
            CoreErrorCode::VerificationFailed
        );

        let mut wrong_audience = oid4vp_request_payload(verifier_did);
        wrong_audience["aud"] = json!("https://wallet.example");
        let wrong_audience = signed(correct_header.clone(), wrong_audience, &verifier);
        assert_eq!(
            verify_oid4vp_request_object(&wrong_audience, &resolver, 1_783_000_100)
                .unwrap_err()
                .code(),
            CoreErrorCode::BindingCheckFailed
        );

        let expired = signed(
            correct_header.clone(),
            oid4vp_request_payload(verifier_did),
            &verifier,
        );
        assert_eq!(
            verify_oid4vp_request_object(&expired, &resolver, 1_783_000_300)
                .unwrap_err()
                .code(),
            CoreErrorCode::FreshnessCheckFailed
        );

        let invalid_requests = [
            (
                "wrong client-id scheme",
                "client_id",
                json!("https://study-space.example/oid4vp"),
                CoreErrorCode::VerificationFailed,
            ),
            (
                "wrong response type",
                "response_type",
                json!("code"),
                CoreErrorCode::VerificationFailed,
            ),
            (
                "wrong response mode",
                "response_mode",
                json!("fragment"),
                CoreErrorCode::VerificationFailed,
            ),
            (
                "unbound response origin",
                "response_uri",
                json!("https://collector.example/oid4vp/response"),
                CoreErrorCode::BindingCheckFailed,
            ),
            (
                "malformed nonce",
                "nonce",
                json!("short nonce!"),
                CoreErrorCode::FreshnessCheckFailed,
            ),
            (
                "non-HTTPS response URI",
                "response_uri",
                json!("http://study-space.example/oid4vp/response"),
                CoreErrorCode::VerificationFailed,
            ),
            (
                "future issued-at",
                "iat",
                json!(1_783_000_106_i64),
                CoreErrorCode::FreshnessCheckFailed,
            ),
            (
                "malformed state",
                "state",
                json!("short state!"),
                CoreErrorCode::FreshnessCheckFailed,
            ),
        ];
        for (name, field, replacement, expected) in invalid_requests {
            let mut payload = oid4vp_request_payload(verifier_did);
            payload[field] = replacement;
            let request = signed(correct_header.clone(), payload, &verifier);
            assert_eq!(
                verify_oid4vp_request_object(&request, &resolver, 1_783_000_100)
                    .unwrap_err()
                    .code(),
                expected,
                "{name}"
            );
        }

        let mut invalid_did = oid4vp_request_payload(verifier_did);
        invalid_did["client_id"] = json!("decentralized_identifier:did:web:");
        let invalid_did = signed(correct_header.clone(), invalid_did, &verifier);
        assert_eq!(
            verify_oid4vp_request_object(&invalid_did, &resolver, 1_783_000_100)
                .unwrap_err()
                .code(),
            CoreErrorCode::VerificationFailed
        );

        for field in [
            "client_id",
            "aud",
            "response_type",
            "response_mode",
            "response_uri",
            "nonce",
            "state",
        ] {
            let mut missing = oid4vp_request_payload(verifier_did);
            missing.as_object_mut().unwrap().remove(field);
            let missing = signed(correct_header.clone(), missing, &verifier);
            assert_eq!(
                verify_oid4vp_request_object(&missing, &resolver, 1_783_000_100)
                    .unwrap_err()
                    .code(),
                CoreErrorCode::VerificationFailed,
                "missing {field}"
            );

            let mut wrong_type = oid4vp_request_payload(verifier_did);
            wrong_type[field] = json!(42);
            let wrong_type = signed(correct_header.clone(), wrong_type, &verifier);
            assert_eq!(
                verify_oid4vp_request_object(&wrong_type, &resolver, 1_783_000_100)
                    .unwrap_err()
                    .code(),
                CoreErrorCode::VerificationFailed,
                "non-string {field}"
            );
        }
        let mut excessive_lifetime = oid4vp_request_payload(verifier_did);
        excessive_lifetime["exp"] = json!(1_783_000_301_i64);
        let excessive_lifetime = signed(correct_header.clone(), excessive_lifetime, &verifier);
        assert_eq!(
            verify_oid4vp_request_object(&excessive_lifetime, &resolver, 1_783_000_100)
                .unwrap_err()
                .code(),
            CoreErrorCode::FreshnessCheckFailed
        );

        let mut ietf_sd_jwt_vc = oid4vp_request_payload(verifier_did);
        ietf_sd_jwt_vc["dcql_query"]["credentials"][0]["format"] = json!("dc+sd-jwt");
        let ietf_sd_jwt_vc = signed(correct_header.clone(), ietf_sd_jwt_vc, &verifier);
        assert!(verify_oid4vp_request_object(&ietf_sd_jwt_vc, &resolver, 1_783_000_100).is_ok());

        let mut unsupported_format = oid4vp_request_payload(verifier_did);
        unsupported_format["dcql_query"]["credentials"][0]["format"] = json!("mso_mdoc");
        let unsupported_format = signed(correct_header.clone(), unsupported_format, &verifier);
        assert_eq!(
            verify_oid4vp_request_object(&unsupported_format, &resolver, 1_783_000_100)
                .unwrap_err()
                .code(),
            CoreErrorCode::VerificationFailed
        );
        for field in ["iat", "exp"] {
            for replacement in [None, Some(json!("not-an-integer"))] {
                let mut payload = oid4vp_request_payload(verifier_did);
                if let Some(replacement) = replacement {
                    payload[field] = replacement;
                } else {
                    payload.as_object_mut().unwrap().remove(field);
                }
                let request = signed(correct_header.clone(), payload, &verifier);
                assert_eq!(
                    verify_oid4vp_request_object(&request, &resolver, 1_783_000_100)
                        .unwrap_err()
                        .code(),
                    CoreErrorCode::VerificationFailed,
                    "invalid {field}"
                );
            }
        }

        let mut redirected = oid4vp_request_payload(verifier_did);
        redirected["redirect_uri"] = json!("https://study-space.example/callback");
        let redirected = signed(correct_header.clone(), redirected, &verifier);
        assert_eq!(
            verify_oid4vp_request_object(&redirected, &resolver, 1_783_000_100)
                .unwrap_err()
                .code(),
            CoreErrorCode::VerificationFailed
        );

        let mut inverted_window = oid4vp_request_payload(verifier_did);
        inverted_window["exp"] = json!(1_783_000_000_i64);
        let inverted_window = signed(correct_header.clone(), inverted_window, &verifier);
        assert_eq!(
            verify_oid4vp_request_object(&inverted_window, &resolver, 1_783_000_100)
                .unwrap_err()
                .code(),
            CoreErrorCode::FreshnessCheckFailed
        );

        for credentials in [None, Some(json!([]))] {
            let mut payload = oid4vp_request_payload(verifier_did);
            if let Some(credentials) = credentials {
                payload["dcql_query"]["credentials"] = credentials;
            } else {
                payload.as_object_mut().unwrap().remove("dcql_query");
            }
            let request = signed(correct_header.clone(), payload, &verifier);
            assert_eq!(
                verify_oid4vp_request_object(&request, &resolver, 1_783_000_100)
                    .unwrap_err()
                    .code(),
                CoreErrorCode::VerificationFailed
            );
        }

        let mut ambiguous_document = document;
        ambiguous_document
            .verification_method
            .push(ambiguous_document.verification_method[0].clone());
        let ambiguous_resolver = FixedResolver {
            url: did_web_to_https_url(verifier_did).unwrap(),
            body: serde_json::to_vec(&ambiguous_document).unwrap(),
        };
        let valid = signed(
            correct_header,
            oid4vp_request_payload(verifier_did),
            &verifier,
        );
        assert_eq!(
            verify_oid4vp_request_object(&valid, &ambiguous_resolver, 1_783_000_100)
                .unwrap_err()
                .code(),
            CoreErrorCode::KeyNotFound
        );
    }

    #[test]
    fn signed_trust_list_enforces_verifier_profile_and_claim_scope() {
        let trust_anchor =
            TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, "trust-anchor-1").unwrap();
        let issuer =
            TestP256Signer::from_private_scalar(&TEST_HOLDER_PRIVATE_SCALAR, "student-issuer-1")
                .unwrap();
        let signed_list = signed_trust_list(&trust_anchor, &issuer, TrustListStatus::Active);
        let approved = vec![
            vec!["credentialSubject".to_owned(), "enrolled".to_owned()],
            vec!["credentialSubject".to_owned(), "institution_id".to_owned()],
        ];

        let result = verify_verifier_trust_list_accreditation(
            &signed_list,
            &trust_anchor.public_jwk,
            "did:web:study-space.example",
            "UniversityEducationCredential",
            "uc3_study_space",
            &approved,
            1_783_380_000,
        )
        .unwrap();

        assert!(result.active);
        assert_eq!(result.claim_paths, approved);

        let overbroad = vec![
            vec!["credentialSubject".to_owned(), "enrolled".to_owned()],
            vec!["credentialSubject".to_owned(), "student_id".to_owned()],
        ];
        assert_eq!(
            verify_verifier_trust_list_accreditation(
                &signed_list,
                &trust_anchor.public_jwk,
                "did:web:study-space.example",
                "UniversityEducationCredential",
                "uc3_study_space",
                &overbroad,
                1_783_380_000,
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::TrustCheckFailed
        );

        assert_eq!(
            verify_verifier_trust_list_accreditation(
                &signed_list,
                &trust_anchor.public_jwk,
                "did:web:unknown.example",
                "UniversityEducationCredential",
                "uc3_study_space",
                &approved,
                1_783_380_000,
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::TrustCheckFailed
        );

        for now in [1_783_375_999, 1_783_400_000] {
            assert_eq!(
                verify_verifier_trust_list_accreditation(
                    &signed_list,
                    &trust_anchor.public_jwk,
                    "did:web:study-space.example",
                    "UniversityEducationCredential",
                    "uc3_study_space",
                    &approved,
                    now,
                )
                .unwrap_err()
                .code(),
                CoreErrorCode::TrustCheckFailed
            );
        }
        assert_eq!(
            verify_verifier_trust_list_accreditation(
                &signed_list,
                &trust_anchor.public_jwk,
                "did:web:study-space.example",
                "UniversityEducationCredential",
                "uc3_study_space",
                &[],
                1_783_380_000,
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::TrustCheckFailed
        );

        let mut inactive_payload = trust_list_payload(&issuer, TrustListStatus::Active);
        inactive_payload.verifiers[0].status = TrustListStatus::Inactive;
        let inactive_list = sign_trust_list(
            &inactive_payload,
            &JwsHeader::es256(
                Some("trust-list+jwt".to_owned()),
                Some("trust-anchor-1".to_owned()),
            ),
            &trust_anchor,
            &trust_anchor.key_id,
        )
        .unwrap();
        assert_eq!(
            verify_verifier_trust_list_accreditation(
                &inactive_list,
                &trust_anchor.public_jwk,
                "did:web:study-space.example",
                "UniversityEducationCredential",
                "uc3_study_space",
                &approved,
                1_783_380_000,
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::TrustCheckFailed
        );
    }

    #[test]
    fn verifier_trust_list_rejects_malformed_scopes_with_stable_codes() {
        let trust_anchor =
            TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, "trust-anchor-1").unwrap();
        let issuer =
            TestP256Signer::from_private_scalar(&TEST_HOLDER_PRIVATE_SCALAR, "student-issuer-1")
                .unwrap();
        let header = JwsHeader::es256(
            Some("trust-list+jwt".to_owned()),
            Some("trust-anchor-1".to_owned()),
        );
        let assert_rejected = |payload: TrustListPayload| {
            assert_eq!(
                sign_trust_list(&payload, &header, &trust_anchor, &trust_anchor.key_id)
                    .unwrap_err()
                    .code(),
                CoreErrorCode::TrustCheckFailed
            );
        };

        for mutate in [
            |entry: &mut VerifierTrustListEntry| entry.verifier_did = "did:key:z6Mk".to_owned(),
            |entry: &mut VerifierTrustListEntry| entry.credential_type.clear(),
            |entry: &mut VerifierTrustListEntry| entry.profile_name.clear(),
            |entry: &mut VerifierTrustListEntry| entry.claim_paths.clear(),
        ] {
            let mut payload = trust_list_payload(&issuer, TrustListStatus::Active);
            mutate(&mut payload.verifiers[0]);
            assert_rejected(payload);
        }

        let mut empty_component = trust_list_payload(&issuer, TrustListStatus::Active);
        empty_component.verifiers[0].claim_paths[0][1].clear();
        assert_rejected(empty_component);

        let mut duplicate = trust_list_payload(&issuer, TrustListStatus::Active);
        duplicate.verifiers.push(duplicate.verifiers[0].clone());
        assert_rejected(duplicate);
    }

    #[test]
    fn did_web_unknown_kid_and_unresolvable_did_name_the_failing_check() {
        let did = "did:web:issuer.unsw.example.edu.au";
        let issuer_key_id = format!("{did}#issuer-1");
        let issuer =
            TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, issuer_key_id.clone())
                .unwrap();
        let holder =
            TestP256Signer::from_private_scalar(&TEST_HOLDER_PRIVATE_SCALAR, "holder-1").unwrap();
        let mut payload = student_vector_payload(&holder.public_jwk);
        payload["iss"] = json!(did);
        payload["issuer"] = json!(did);
        let mut salts = FixedSaltSource::new((0_u8..8).map(|index| vec![index; 16]));
        let document =
            build_did_web_document(did, std::slice::from_ref(&issuer.public_jwk)).unwrap();
        let resolver = FixedResolver {
            url: did_web_to_https_url(did).unwrap(),
            body: serde_json::to_vec(&document).unwrap(),
        };
        let bad_kid_header = JwsHeader::es256(
            Some(VC_SD_JWT_TYP.to_owned()),
            Some(format!("{did}#missing")),
        );
        let bad_kid = issue_sd_jwt(
            payload.clone(),
            &student_disclosure_specs(),
            0,
            &bad_kid_header,
            &issuer,
            &issuer.key_id,
            &mut salts,
        )
        .unwrap();

        assert_eq!(
            verify_compact_jws_with_did_web_issuer(&bad_kid.issuer_jwt, &resolver)
                .unwrap_err()
                .code(),
            CoreErrorCode::KeyNotFound
        );

        for mutate in [
            |method: &mut DidVerificationMethod| method.type_ = "JsonWebKey2020".to_owned(),
            |method: &mut DidVerificationMethod| {
                method.controller = "did:web:different.example".to_owned()
            },
        ] {
            let mut untrusted_document = document.clone();
            mutate(&mut untrusted_document.verification_method[0]);
            let untrusted_resolver = FixedResolver {
                url: did_web_to_https_url(did).unwrap(),
                body: serde_json::to_vec(&untrusted_document).unwrap(),
            };
            assert_eq!(
                resolve_did_web_key(did, issuer.key_id.as_str(), &untrusted_resolver)
                    .unwrap_err()
                    .code(),
                CoreErrorCode::InvalidKey
            );
        }

        let good_header = JwsHeader::es256(Some(VC_SD_JWT_TYP.to_owned()), Some(issuer_key_id));
        let mut salts = FixedSaltSource::new((0_u8..8).map(|index| vec![index; 16]));
        let good = issue_sd_jwt(
            payload,
            &student_disclosure_specs(),
            0,
            &good_header,
            &issuer,
            &issuer.key_id,
            &mut salts,
        )
        .unwrap();
        let missing_resolver = FixedResolver {
            url: "https://other.example/.well-known/did.json".to_owned(),
            body: b"{}".to_vec(),
        };

        assert_eq!(
            verify_compact_jws_with_did_web_issuer(&good.issuer_jwt, &missing_resolver)
                .unwrap_err()
                .code(),
            CoreErrorCode::ResolverUnavailable
        );
    }

    #[test]
    fn bitstring_status_list_uses_w3c_leftmost_bit_ordering() {
        let encoded =
            encode_bitstring_status_list(DEFAULT_STATUS_LIST_BITS, &[0, 7, 8, 42]).unwrap();
        let decoded = decode_bitstring_status_list(&encoded).unwrap();

        assert_eq!(decoded[0], 0b1000_0001);
        assert_eq!(decoded[1], 0b1000_0000);
        assert!(bitstring_status_at(&encoded, 0).unwrap());
        assert!(bitstring_status_at(&encoded, 7).unwrap());
        assert!(bitstring_status_at(&encoded, 8).unwrap());
        assert!(bitstring_status_at(&encoded, 42).unwrap());
        assert!(!bitstring_status_at(&encoded, 41).unwrap());
    }

    #[test]
    fn bitstring_status_list_size_is_sane_for_realistic_cohort() {
        let encoded =
            encode_bitstring_status_list(DEFAULT_STATUS_LIST_BITS, &[42, 4096, 65_535]).unwrap();
        let report = status_list_size_report(DEFAULT_STATUS_LIST_BITS, &encoded).unwrap();

        assert_eq!(report.uncompressed_bytes, 16 * 1024);
        assert!(
            report.encoded_list_bytes < 400,
            "sparse 131,072-bit revocation list should gzip to a few hundred bytes"
        );
    }

    #[test]
    fn resolves_active_and_revoked_status_through_injected_resolver() {
        let signer = TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, "issuer-1").unwrap();
        let encoded = encode_bitstring_status_list(DEFAULT_STATUS_LIST_BITS, &[42]).unwrap();
        let header = JwsHeader::es256(
            Some("status-list+jwt".to_owned()),
            Some("issuer-1".to_owned()),
        );
        let signed_list = sign_bitstring_status_list_credential(
            &status_list_payload(encoded),
            &header,
            &signer,
            &signer.key_id,
        )
        .unwrap();
        let resolver = FixedResolver {
            url: "https://status.unsw.example/status/1".to_owned(),
            body: signed_list.into_bytes(),
        };

        let revoked =
            resolve_credential_status(&status_entry(42), &resolver, &signer.public_jwk).unwrap();
        let active =
            resolve_credential_status(&status_entry(41), &resolver, &signer.public_jwk).unwrap();

        assert!(revoked.revoked);
        assert!(!active.revoked);
        assert_eq!(
            verify_credential_status_active(&status_entry(42), &resolver, &signer.public_jwk)
                .unwrap_err()
                .code(),
            CoreErrorCode::StatusCheckFailed
        );
        verify_credential_status_active(&status_entry(41), &resolver, &signer.public_jwk).unwrap();
        assert_eq!(
            verify_credential_status_active_at(
                &status_entry(41),
                &resolver,
                &signer.public_jwk,
                1_814_400_000,
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::StatusListStale
        );
    }

    #[test]
    fn status_list_signature_is_validated_before_bits_are_trusted() {
        let signer = TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, "issuer-1").unwrap();
        let encoded = encode_bitstring_status_list(DEFAULT_STATUS_LIST_BITS, &[]).unwrap();
        let header = JwsHeader::es256(
            Some("status-list+jwt".to_owned()),
            Some("issuer-1".to_owned()),
        );
        let signed_list = sign_bitstring_status_list_credential(
            &status_list_payload(encoded),
            &header,
            &signer,
            &signer.key_id,
        )
        .unwrap();
        let mut parts = signed_list
            .split('.')
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let mut payload = decode_jws_payload_unverified(&signed_list).unwrap();
        payload["credentialSubject"]["encodedList"] =
            json!(encode_bitstring_status_list(DEFAULT_STATUS_LIST_BITS, &[42]).unwrap());
        parts[1] = b64_encode(&serde_json::to_vec(&payload).unwrap());
        let tampered_list = parts.join(".");
        let resolver = FixedResolver {
            url: "https://status.unsw.example/status/1".to_owned(),
            body: tampered_list.into_bytes(),
        };

        assert_eq!(
            resolve_credential_status(&status_entry(42), &resolver, &signer.public_jwk)
                .unwrap_err()
                .code(),
            CoreErrorCode::InvalidSignature
        );
    }

    #[test]
    fn status_list_is_bound_to_the_referenced_list_and_credential_issuer() {
        let signer = TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, "issuer-1").unwrap();
        let encoded = encode_bitstring_status_list(DEFAULT_STATUS_LIST_BITS, &[42]).unwrap();
        let header = JwsHeader::es256(
            Some("status-list+jwt".to_owned()),
            Some("issuer-1".to_owned()),
        );
        let mut wrong_list = status_list_payload(encoded.clone());
        wrong_list.credential_subject.id =
            "https://status.unsw.example/status/other#list".to_owned();
        let signed_wrong_list =
            sign_bitstring_status_list_credential(&wrong_list, &header, &signer, &signer.key_id)
                .unwrap();
        let wrong_list_resolver = FixedResolver {
            url: "https://status.unsw.example/status/1".to_owned(),
            body: signed_wrong_list.into_bytes(),
        };
        assert_eq!(
            resolve_credential_status(&status_entry(42), &wrong_list_resolver, &signer.public_jwk,)
                .unwrap_err()
                .code(),
            CoreErrorCode::StatusCheckFailed
        );

        let mut wrong_issuer = status_list_payload(encoded);
        wrong_issuer.issuer = "did:web:other.example".to_owned();
        let signed_wrong_issuer =
            sign_bitstring_status_list_credential(&wrong_issuer, &header, &signer, &signer.key_id)
                .unwrap();
        let wrong_issuer_resolver = FixedResolver {
            url: "https://status.unsw.example/status/1".to_owned(),
            body: signed_wrong_issuer.into_bytes(),
        };
        assert_eq!(
            resolve_credential_status_at_for_issuer(
                &status_entry(42),
                &wrong_issuer_resolver,
                &signer.public_jwk,
                "did:web:issuer.unsw.example.edu.au",
                1_783_376_100,
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::StatusCheckFailed
        );
    }

    #[test]
    fn signed_trust_list_verifies_and_accredits_student_issuer_offline() {
        let trust_anchor =
            TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, "trust-anchor-1").unwrap();
        let student_issuer = TestP256Signer::from_private_scalar(
            &TEST_HOLDER_PRIVATE_SCALAR,
            "did:web:issuer.unsw.example.edu.au#issuer-1",
        )
        .unwrap();
        let signed_list =
            signed_trust_list(&trust_anchor, &student_issuer, TrustListStatus::Active);

        let (header, payload) = verify_trust_list(&signed_list, &trust_anchor.public_jwk).unwrap();
        let result = verify_trust_list_accreditation(
            &signed_list,
            &trust_anchor.public_jwk,
            "did:web:issuer.unsw.example.edu.au",
            "UniversityEducationCredential",
            &student_issuer.public_jwk,
            1_783_376_100,
        )
        .unwrap();

        assert_eq!(header.typ.as_deref(), Some("trust-list+jwt"));
        assert_eq!(payload.entries.len(), 1);
        assert!(result.active);
        assert_eq!(
            result.public_jwk_sha256_thumbprint,
            public_jwk_sha256_thumbprint(&student_issuer.public_jwk).unwrap()
        );
    }

    #[test]
    fn trust_list_names_negative_accreditation_checks() {
        let trust_anchor =
            TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, "trust-anchor-1").unwrap();
        let student_issuer = TestP256Signer::from_private_scalar(
            &TEST_HOLDER_PRIVATE_SCALAR,
            "did:web:issuer.unsw.example.edu.au#issuer-1",
        )
        .unwrap();
        let signed_list =
            signed_trust_list(&trust_anchor, &student_issuer, TrustListStatus::Active);

        assert_eq!(
            verify_trust_list_accreditation(
                &signed_list,
                &trust_anchor.public_jwk,
                "did:web:rogue.example.edu.au",
                "UniversityEducationCredential",
                &student_issuer.public_jwk,
                1_783_376_100,
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::TrustCheckFailed
        );
        assert_eq!(
            verify_trust_list_accreditation(
                &signed_list,
                &trust_anchor.public_jwk,
                "did:web:issuer.unsw.example.edu.au",
                "RoleAuthorityCredential",
                &student_issuer.public_jwk,
                1_783_376_100,
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::TrustCheckFailed
        );
        assert_eq!(
            verify_trust_list_accreditation(
                &signed_trust_list(&trust_anchor, &student_issuer, TrustListStatus::Inactive),
                &trust_anchor.public_jwk,
                "did:web:issuer.unsw.example.edu.au",
                "UniversityEducationCredential",
                &student_issuer.public_jwk,
                1_783_376_100,
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::TrustCheckFailed
        );
        assert_eq!(
            verify_trust_list_accreditation(
                &signed_list,
                &trust_anchor.public_jwk,
                "did:web:issuer.unsw.example.edu.au",
                "UniversityEducationCredential",
                &trust_anchor.public_jwk,
                1_783_376_100,
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::TrustCheckFailed
        );
        assert_eq!(
            verify_trust_list_accreditation(
                &signed_list,
                &trust_anchor.public_jwk,
                "did:web:issuer.unsw.example.edu.au",
                "UniversityEducationCredential",
                &student_issuer.public_jwk,
                1_783_400_001,
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::TrustCheckFailed
        );
    }

    #[test]
    fn imports_rfc9901_p256_public_jwk_exactly() {
        let issuer_jwk = PublicJwk::p256(RFC9901_ISSUER_JWK_X, RFC9901_ISSUER_JWK_Y, None);
        let verifying_key = verifying_key_from_jwk(&issuer_jwk).unwrap();

        assert_eq!(
            verifying_key.to_sec1_point(false).as_bytes(),
            RFC9901_ISSUER_SEC1
        );
    }

    #[test]
    fn verifies_rfc9901_example_issuer_signature() {
        let issuer_jwk = PublicJwk::p256(RFC9901_ISSUER_JWK_X, RFC9901_ISSUER_JWK_Y, None);
        let issuer_jwt = concat!(
            "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.",
            "eyJfc2QiOiBbIkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZ",
            "akg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBL",
            "dVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1",
            "SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tB",
            "TmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2",
            "Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFr",
            "b2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpn",
            "bGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vaXNzdWVyLmV4YW1wbGUu",
            "Y29tIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjog",
            "InVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15",
            "VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1",
            "ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjog",
            "InNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0y",
            "NTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VH",
            "ZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlG",
            "MkhaUSJ9fX0.",
            "MczwjBFGtzf-6WMT-hIvYbkb11NrV1WMO-jTijpMPNbswNzZ87wY2uHz",
            "-CXo6R04b7jYrpj9mNRAvVssXou1iw",
        );

        let verified = verify_compact_jws(issuer_jwt, &issuer_jwk).unwrap();

        assert_eq!(verified.header.alg, "ES256");
        let payload: Value = serde_json::from_slice(&verified.payload).unwrap();
        assert_eq!(payload["_sd_alg"], "sha-256");
    }

    #[test]
    fn verifies_rfc9901_disclosure_digest_vector() {
        let disclosure = concat!(
            "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInN1YiIsICI2YzVjMGE0OS1iNTg",
            "5LTQzMWQtYmFlNy0yMTkxMjJhOWVjMmMiXQ"
        );
        let decoded = decode_disclosure(disclosure).unwrap();

        assert_eq!(decoded.claim_name, "sub");
        assert_eq!(
            decoded.digest,
            "X6ZAYOII2vPN40V7xExZwVwz7yRmLNcVwt5DL8RLv4g"
        );
    }

    #[test]
    fn verifies_committed_webapp_explainer_uc3_and_uc4_presentations() {
        let fixture = fixture_value();
        let issuer_jwk = fixture_issuer_jwk(&fixture);
        let uc3 = &fixture["presentations"]["uc3_study_space"];
        let uc4 = &fixture["presentations"]["uc4_exam_hall"];

        let uc3_verified = verify_sd_jwt_presentation(
            uc3["sd_jwt_kb"].as_str().unwrap(),
            &issuer_jwk,
            &SdJwtVerificationOptions::for_profile(
                uc3["audience"].as_str().unwrap(),
                uc3["nonce"].as_str().unwrap(),
                uc3["iat"].as_i64().unwrap() + 10,
                &DisclosureProfile::uc3_study_space(),
            ),
        )
        .unwrap();
        let uc4_verified = verify_sd_jwt_presentation(
            uc4["sd_jwt_kb"].as_str().unwrap(),
            &issuer_jwk,
            &SdJwtVerificationOptions::for_profile(
                uc4["audience"].as_str().unwrap(),
                uc4["nonce"].as_str().unwrap(),
                uc4["iat"].as_i64().unwrap() + 10,
                &DisclosureProfile::uc4_exam_hall(),
            ),
        )
        .unwrap();

        assert_eq!(uc3_verified.issuer_header.typ.as_deref(), Some("vc+sd-jwt"));
        assert_eq!(uc3_verified.kb_header.typ.as_deref(), Some("kb+jwt"));
        assert_eq!(
            uc3_verified.processed_payload["iss"],
            json!("https://issuer.unsw.edu.au")
        );
        assert_eq!(
            uc3_verified.processed_payload["credentialSubject"]["institution_id"],
            json!("unsw.edu.au")
        );
        assert_eq!(
            uc3_verified.processed_payload["credentialSubject"]["enrolled"],
            json!(true)
        );
        assert!(uc3_verified.processed_payload["credentialSubject"]["photo_hash"].is_null());

        assert_eq!(
            uc4_verified.processed_payload["credentialSubject"]["photo_hash"],
            json!("6EoT5S7F9B0x3uYcSO7tmQeI6dAUcFxxS4M1blj6Vb0")
        );
        assert_eq!(
            uc4_verified.processed_payload["credentialSubject"]["student_id"],
            json!("z5555555")
        );
    }

    #[test]
    fn presentation_freshness_applies_exact_future_skew_and_past_age_boundaries() {
        let fixture = fixture_value();
        let issuer_jwk = fixture_issuer_jwk(&fixture);
        let uc3 = &fixture["presentations"]["uc3_study_space"];
        let iat = uc3["iat"].as_i64().unwrap();
        let mut options = SdJwtVerificationOptions::for_profile(
            uc3["audience"].as_str().unwrap(),
            uc3["nonce"].as_str().unwrap(),
            iat - 5,
            &DisclosureProfile::uc3_study_space(),
        );
        options.max_kb_future_skew_seconds = 5;
        options.max_kb_age_seconds = 300;

        verify_sd_jwt_presentation(uc3["sd_jwt_kb"].as_str().unwrap(), &issuer_jwk, &options)
            .unwrap();

        options.now_unix_seconds = iat - 6;
        assert_eq!(
            verify_sd_jwt_presentation(uc3["sd_jwt_kb"].as_str().unwrap(), &issuer_jwk, &options,)
                .unwrap_err()
                .code(),
            CoreErrorCode::FreshnessCheckFailed
        );

        options.now_unix_seconds = iat + 301;
        assert_eq!(
            verify_sd_jwt_presentation(uc3["sd_jwt_kb"].as_str().unwrap(), &issuer_jwk, &options,)
                .unwrap_err()
                .code(),
            CoreErrorCode::FreshnessCheckFailed
        );
    }

    #[test]
    fn reproduces_committed_webapp_explainer_non_signature_artifacts_from_salts() {
        let fixture = fixture_value();
        let issuer = TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, "issuer-1").unwrap();
        let holder_jwk: PublicJwk =
            serde_json::from_value(fixture["holder_public_jwk"].clone()).unwrap();
        let header = JwsHeader::es256(Some(VC_SD_JWT_TYP.to_owned()), Some("issuer-1".to_owned()));
        let mut salts = fixed_salts_from_fixture(&fixture);

        let issued = issue_sd_jwt(
            student_vector_payload(&holder_jwk),
            &student_disclosure_specs(),
            0,
            &header,
            &issuer,
            &issuer.key_id,
            &mut salts,
        )
        .unwrap();
        let reproduced_disclosures = issued
            .disclosures
            .iter()
            .map(|disclosure| {
                json!({
                    "path": disclosure.full_path(),
                    "salt_bytes": disclosure.salt,
                    "salt": disclosure.salt,
                    "encoded": disclosure.encoded,
                    "digest": disclosure.digest
                })
            })
            .collect::<Vec<_>>();

        assert_eq!(issued.payload, fixture["sd_payload"]);
        assert_eq!(Value::Array(reproduced_disclosures), fixture["disclosures"]);
        let reproduced_payload_bytes = serde_json::to_vec(&issued.payload).unwrap();
        let committed_payload_segment = fixture["issuer_jwt"]
            .as_str()
            .unwrap()
            .split('.')
            .nth(1)
            .unwrap();
        assert_eq!(
            b64_encode(&reproduced_payload_bytes),
            committed_payload_segment
        );
        assert_eq!(
            decode_jws_payload_unverified(&issued.issuer_jwt).unwrap(),
            fixture["sd_payload"]
        );
    }

    #[test]
    fn disclosure_profiles_select_only_their_constitutional_claims() {
        let fixture = fixture_value();
        let holder =
            TestP256Signer::from_private_scalar(&TEST_HOLDER_PRIVATE_SCALAR, "holder-1").unwrap();
        let uc3 = present_sd_jwt(
            fixture["sd_jwt"].as_str().unwrap(),
            &DisclosureProfile::uc3_study_space(),
            &holder,
            &holder.key_id,
            "https://study-space.example/oid4vp",
            "fresh-uc3",
            1783000300,
        )
        .unwrap();
        let uc4 = present_sd_jwt(
            fixture["sd_jwt"].as_str().unwrap(),
            &DisclosureProfile::uc4_exam_hall(),
            &holder,
            &holder.key_id,
            "https://exam-hall.example/oid4vp",
            "fresh-uc4",
            1783000400,
        )
        .unwrap();

        let uc3_claim_names = uc3
            .selected_disclosures
            .iter()
            .map(|disclosure| decode_disclosure(disclosure).unwrap().claim_name)
            .collect::<Vec<_>>();
        let uc4_claim_names = uc4
            .selected_disclosures
            .iter()
            .map(|disclosure| decode_disclosure(disclosure).unwrap().claim_name)
            .collect::<Vec<_>>();

        assert_eq!(uc3_claim_names, vec!["enrolled"]);
        assert_eq!(
            uc4_claim_names,
            vec![
                "enrolled",
                "family_name",
                "given_name",
                "student_id",
                "photo_hash"
            ]
        );
    }

    #[test]
    fn issuance_can_add_decoy_digests_without_extra_disclosures() {
        let issuer = TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, "issuer-1").unwrap();
        let holder =
            TestP256Signer::from_private_scalar(&TEST_HOLDER_PRIVATE_SCALAR, "holder-1").unwrap();
        let header = JwsHeader::es256(Some(VC_SD_JWT_TYP.to_owned()), Some("issuer-1".to_owned()));
        let mut salts = FixedSaltSource::new([
            vec![0x10; SD_JWT_SALT_BYTES],
            vec![0x77; 32],
            vec![0x88; 32],
        ]);

        let issued = issue_sd_jwt(
            student_vector_payload(&holder.public_jwk),
            &[DisclosureSpec::new(["credentialSubject"], "enrolled")],
            2,
            &header,
            &issuer,
            &issuer.key_id,
            &mut salts,
        )
        .unwrap();

        assert_eq!(issued.disclosures.len(), 1);
        assert_eq!(
            issued.payload["_sd"].as_array().unwrap().len(),
            2,
            "decoys are payload digests only, not holder disclosures"
        );
    }

    #[test]
    fn sd_jwt_negative_cases_name_stable_error_codes() {
        let fixture = fixture_value();
        let issuer_jwk = fixture_issuer_jwk(&fixture);
        let uc3 = &fixture["presentations"]["uc3_study_space"];
        let options = SdJwtVerificationOptions::for_profile(
            uc3["audience"].as_str().unwrap(),
            uc3["nonce"].as_str().unwrap(),
            uc3["iat"].as_i64().unwrap() + 10,
            &DisclosureProfile::uc3_study_space(),
        );

        let mut parts = uc3["sd_jwt_kb"]
            .as_str()
            .unwrap()
            .split('~')
            .map(str::to_owned)
            .collect::<Vec<_>>();
        parts[1] = encode_disclosure("EBAQEBAQEBAQEBAQEBAQEA", "enrolled", &json!(false)).unwrap();
        let tampered = parts.join("~");
        assert_eq!(
            verify_sd_jwt_presentation(&tampered, &issuer_jwk, &options)
                .unwrap_err()
                .code(),
            CoreErrorCode::DisclosureDigestMismatch
        );

        let mut wrong_nonce = options.clone();
        wrong_nonce.nonce = "wrong-nonce".to_owned();
        assert_eq!(
            verify_sd_jwt_presentation(
                uc3["sd_jwt_kb"].as_str().unwrap(),
                &issuer_jwk,
                &wrong_nonce
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::BindingCheckFailed
        );

        let mut wrong_audience = options.clone();
        wrong_audience.audience = "https://other.example/oid4vp".to_owned();
        assert_eq!(
            verify_sd_jwt_presentation(
                uc3["sd_jwt_kb"].as_str().unwrap(),
                &issuer_jwk,
                &wrong_audience
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::BindingCheckFailed
        );

        let missing_disclosure = {
            let mut parts = uc3["sd_jwt_kb"]
                .as_str()
                .unwrap()
                .split('~')
                .collect::<Vec<_>>();
            parts.remove(1);
            parts.join("~")
        };
        assert_eq!(
            verify_sd_jwt_presentation(&missing_disclosure, &issuer_jwk, &options)
                .unwrap_err()
                .code(),
            CoreErrorCode::MissingDisclosure
        );

        let mut expired = options;
        expired.now_unix_seconds = 1883000001;
        assert_eq!(
            verify_sd_jwt_presentation(uc3["sd_jwt_kb"].as_str().unwrap(), &issuer_jwk, &expired)
                .unwrap_err()
                .code(),
            CoreErrorCode::FreshnessCheckFailed
        );
    }

    #[test]
    fn vc_payload_round_trips_through_compact_jws() {
        let signer = TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, "issuer-1").unwrap();
        let payload = VerifiableCredentialPayload {
            context: vec!["https://www.w3.org/ns/credentials/v2".to_owned()],
            type_: vec![
                "VerifiableCredential".to_owned(),
                "UniversityEducationCredential".to_owned(),
            ],
            issuer: "did:web:issuer.unsw.example.edu.au".to_owned(),
            credential_subject: json!({
                "institution_id": "unsw.edu.au",
                "enrolled": true
            }),
            credential_status: Some(CredentialStatus {
                id: "https://status.example.edu.au/1#42".to_owned(),
                type_: "BitstringStatusListEntry".to_owned(),
                status_purpose: "revocation".to_owned(),
                status_list_index: "42".to_owned(),
                status_list_credential: "https://status.example.edu.au/1".to_owned(),
            }),
            cnf: Some(Confirmation {
                jwk: signer.public_jwk.clone(),
            }),
            valid_from: Some("2026-01-01T00:00:00Z".to_owned()),
            valid_until: Some("2027-01-01T00:00:00Z".to_owned()),
        };
        let header = JwsHeader::es256(Some("vc+sd-jwt".to_owned()), Some("issuer-1".to_owned()));

        let compact = sign_compact_jws_json(&header, &payload, &signer, &signer.key_id).unwrap();
        let (verified_header, verified_payload): (JwsHeader, VerifiableCredentialPayload) =
            verify_compact_jws_json(&compact, &signer.public_jwk).unwrap();

        assert_eq!(verified_header, header);
        assert_eq!(verified_payload, payload);
    }

    #[test]
    fn compact_jws_rejects_wrong_signature_with_stable_code() {
        let signer = TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, "issuer-1").unwrap();
        let header = JwsHeader::es256(Some("JWT".to_owned()), Some("issuer-1".to_owned()));
        let compact =
            sign_compact_jws(&header, br#"{"sub":"123"}"#, &signer, &signer.key_id).unwrap();
        let mut parts: Vec<String> = compact.split('.').map(str::to_owned).collect();
        parts[1] = b64_encode(br#"{"sub":"456"}"#);
        let tampered = parts.join(".");

        let error = verify_compact_jws(&tampered, &signer.public_jwk).unwrap_err();

        assert_eq!(error.code(), CoreErrorCode::InvalidSignature);
    }

    #[test]
    fn public_jws_signing_uses_key_handles() {
        let signer =
            TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, "issuer-handle").unwrap();
        let header = JwsHeader::es256(Some("JWT".to_owned()), Some("issuer-handle".to_owned()));

        let compact = sign_compact_jws(&header, br#"{"sub":"123"}"#, &signer, &signer.key_id)
            .expect("test signer signs through KeyId handle");
        let verified = verify_compact_jws(&compact, &signer.public_jwk).unwrap();

        assert_eq!(verified.payload, br#"{"sub":"123"}"#);
    }

    #[test]
    fn oid4vci_named_proof_profiles_are_constructed_and_signed_in_core() {
        let attester =
            TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, "suite-attester").unwrap();
        let holder =
            TestP256Signer::from_private_scalar(&TEST_HOLDER_PRIVATE_SCALAR, "wallet-instance")
                .unwrap();

        let holder_proof = create_oid4vci_holder_proof(
            "https://issuer.example/",
            "credential-nonce",
            1_783_000_100,
            &holder.public_jwk,
            &holder,
            &holder.key_id,
        )
        .unwrap();
        let (holder_header, holder_claims): (JwsHeader, Value) =
            verify_compact_jws_json(&holder_proof, &holder.public_jwk).unwrap();
        assert_eq!(holder_header.typ.as_deref(), Some("openid4vci-proof+jwt"));
        assert_eq!(holder_header.jwk.as_ref(), Some(&holder.public_jwk));
        assert_eq!(holder_claims["nonce"], "credential-nonce");

        let dpop = create_oid4vci_dpop_proof(
            "POST",
            "https://issuer.example/token",
            1_783_000_100,
            "proof-id",
            Some("dpop-nonce"),
            Some("access-token"),
            &holder.public_jwk,
            &holder,
            &holder.key_id,
        )
        .unwrap();
        let (dpop_header, dpop_claims): (JwsHeader, Value) =
            verify_compact_jws_json(&dpop, &holder.public_jwk).unwrap();
        assert_eq!(dpop_header.typ.as_deref(), Some("dpop+jwt"));
        assert_eq!(dpop_claims["htm"], "POST");
        assert_eq!(dpop_claims["nonce"], "dpop-nonce");
        assert_eq!(dpop_claims["ath"], sha256_b64url("access-token".as_bytes()));

        let attestation = create_oid4vci_client_attestation(
            "https://attester.example",
            "52480754053",
            1_783_000_100,
            &["public-leaf".to_owned()],
            &holder.public_jwk,
            &attester.public_jwk,
            &attester,
            &attester.key_id,
        )
        .unwrap();
        let (attestation_header, attestation_claims): (JwsHeader, Value) =
            verify_compact_jws_json(&attestation, &attester.public_jwk).unwrap();
        assert_eq!(
            attestation_header.typ.as_deref(),
            Some("oauth-client-attestation+jwt")
        );
        assert_eq!(attestation_header.x5c, Some(vec!["public-leaf".to_owned()]));
        assert_eq!(attestation_claims["sub"], "52480754053");
        assert_eq!(attestation_claims["cnf"]["jwk"], json!(holder.public_jwk));

        let attestation_pop = create_oid4vci_client_attestation_pop(
            "52480754053",
            "https://issuer.example/",
            1_783_000_100,
            "attestation-proof-id",
            Some("challenge"),
            &holder.public_jwk,
            &holder,
            &holder.key_id,
        )
        .unwrap();
        let (pop_header, pop_claims): (JwsHeader, Value) =
            verify_compact_jws_json(&attestation_pop, &holder.public_jwk).unwrap();
        assert_eq!(
            pop_header.typ.as_deref(),
            Some("oauth-client-attestation-pop+jwt")
        );
        assert_eq!(pop_claims["challenge"], "challenge");
    }

    #[test]
    fn oid4vci_https_profiles_reject_malformed_authorities_and_fragments() {
        let holder =
            TestP256Signer::from_private_scalar(&TEST_HOLDER_PRIVATE_SCALAR, "holder").unwrap();

        for target in [
            "https://:443/token",
            "https://user@issuer.example/token",
            "https://issuer.example/token#fragment",
        ] {
            let error = create_oid4vci_dpop_proof(
                "POST",
                target,
                1_783_000_100,
                "proof-id",
                None,
                None,
                &holder.public_jwk,
                &holder,
                &holder.key_id,
            )
            .unwrap_err();
            assert_eq!(error.code(), CoreErrorCode::InvalidInput, "{target}");
        }
    }

    #[test]
    fn external_holder_signing_finalizes_oid4vci_proofs_and_rejects_tampering() {
        let holder =
            TestP256Signer::from_private_scalar(&TEST_HOLDER_PRIVATE_SCALAR, "platform-holder-1")
                .unwrap();
        let prepared = prepare_oid4vci_key_proof_external(
            "https://issuer.example",
            "c-nonce-1",
            1_783_000_100,
            &holder.key_id,
            &holder.public_jwk,
        )
        .unwrap();

        assert_eq!(prepared.algorithm, "ES256");
        assert_eq!(prepared.key_id, holder.key_id);
        assert_eq!(prepared.public_jwk, holder.public_jwk);
        let signature = holder.sign_es256(prepared.signing_input.as_bytes());
        let proof = finalize_oid4vci_key_proof_external(
            &prepared,
            &signature,
            ExternalSignatureFormat::P1363,
        )
        .unwrap();
        let (header, payload): (JwsHeader, Value) =
            verify_compact_jws_json(&proof, &holder.public_jwk).unwrap();

        assert_eq!(header.typ.as_deref(), Some("openid4vci-proof+jwt"));
        assert_eq!(payload["aud"], "https://issuer.example");
        assert_eq!(payload["nonce"], "c-nonce-1");
        assert_eq!(payload["iat"], 1_783_000_100_i64);

        let mut tampered = prepared.clone();
        tampered.signing_input.push('x');
        assert_eq!(
            finalize_oid4vci_key_proof_external(
                &tampered,
                &signature,
                ExternalSignatureFormat::P1363,
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::InvalidSignature
        );
        assert_eq!(
            finalize_oid4vci_key_proof_external(
                &prepared,
                &[0_u8; 7],
                ExternalSignatureFormat::P1363,
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::InvalidSignature
        );
        let wrong_holder =
            TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, "platform-holder-1").unwrap();
        let mut wrong_key = prepared.clone();
        wrong_key.public_jwk = wrong_holder.public_jwk;
        assert_eq!(
            finalize_oid4vci_key_proof_external(
                &wrong_key,
                &signature,
                ExternalSignatureFormat::P1363,
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::InvalidSignature
        );
    }

    #[test]
    fn external_holder_signing_finalizes_kb_jwt_from_native_der() {
        let issuer =
            TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, "issuer-external").unwrap();
        let holder =
            TestP256Signer::from_private_scalar(&TEST_HOLDER_PRIVATE_SCALAR, "platform-holder-1")
                .unwrap();
        let header = JwsHeader::es256(
            Some(VC_SD_JWT_TYP.to_owned()),
            Some(issuer.key_id.as_str().to_owned()),
        );
        let mut salts = FixedSaltSource::new((0_u8..8).map(|index| vec![index; 16]));
        let issued = issue_sd_jwt(
            student_vector_payload(&holder.public_jwk),
            &student_disclosure_specs(),
            0,
            &header,
            &issuer,
            &issuer.key_id,
            &mut salts,
        )
        .unwrap();
        let prepared = prepare_sd_jwt_presentation_external(
            &issued.compact,
            &DisclosureProfile::uc3_study_space(),
            &holder.key_id,
            &holder.public_jwk,
            "https://study-space.example/oid4vp",
            "nonce-external",
            1_783_000_100,
        )
        .unwrap();
        let wrong_holder =
            TestP256Signer::from_private_scalar(&TEST_PRIVATE_SCALAR, "wrong-platform-holder")
                .unwrap();
        assert_eq!(
            prepare_sd_jwt_presentation_external(
                &issued.compact,
                &DisclosureProfile::uc3_study_space(),
                &wrong_holder.key_id,
                &wrong_holder.public_jwk,
                "https://study-space.example/oid4vp",
                "nonce-external",
                1_783_000_100,
            )
            .unwrap_err()
            .code(),
            CoreErrorCode::BindingCheckFailed
        );
        let raw_signature = holder.sign_es256(prepared.jws.signing_input.as_bytes());
        let der_signature = Signature::from_slice(&raw_signature).unwrap().to_der();
        let presentation = finalize_sd_jwt_presentation_external(
            &prepared,
            der_signature.as_bytes(),
            ExternalSignatureFormat::Asn1Der,
        )
        .unwrap();
        let verified = verify_sd_jwt_presentation(
            &presentation.presentation,
            &issuer.public_jwk,
            &SdJwtVerificationOptions::for_profile(
                "https://study-space.example/oid4vp",
                "nonce-external",
                1_783_000_101,
                &DisclosureProfile::uc3_study_space(),
            ),
        )
        .unwrap();

        assert_eq!(presentation.disclosed_sd_jwt, prepared.disclosed_sd_jwt);
        assert_eq!(presentation.sd_hash, prepared.sd_hash);
        assert_eq!(
            verified.processed_payload["credentialSubject"]["enrolled"],
            true
        );
    }
}
