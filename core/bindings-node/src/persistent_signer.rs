//! Filesystem adapter for the core's encrypted signing handle.
use identity_core::{
    CoreError, CoreErrorCode, CoreResult, KeyId, KeyStore, LocalSigner, PublicJwk, Signer,
    b64_decode,
};
use napi::{Error, Result, Status};
use napi_derive::napi;
use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::{Read, Write},
    sync::{Mutex, OnceLock},
};
use zeroize::Zeroizing;

// ponytail: one mutex serializes local signatures; use per-key locks if signing throughput requires it.
static KEYS: OnceLock<Mutex<HashMap<String, LocalSigner>>> = OnceLock::new();
fn keys() -> &'static Mutex<HashMap<String, LocalSigner>> {
    KEYS.get_or_init(|| Mutex::new(HashMap::new()))
}
fn unavailable() -> CoreError {
    CoreError::new(
        CoreErrorCode::InvalidKey,
        "persistent signing identity unavailable or locked",
    )
}

#[napi(js_name = "persistentSigningKeyRaw")]
pub fn persistent_signing_key_raw(
    path: String,
    unlock_key: String,
    key_id: String,
    create: bool,
) -> Result<String> {
    let unlock_key = Zeroizing::new(unlock_key);
    let unlock = Zeroizing::new(b64_decode(&unlock_key).map_err(super::to_napi_error)?);
    let id = KeyId::new(&key_id);
    let result = (|| -> CoreResult<PublicJwk> {
        let mut keys = keys().lock().map_err(|_| unavailable())?;
        if keys.contains_key(&key_id) {
            return Err(unavailable());
        }
        let signer = if create {
            let signer = LocalSigner::generate(id.clone())?;
            let sealed = signer.seal(&unlock)?;
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&path).map_err(|_| unavailable())?;
            file.write_all(&sealed)
                .and_then(|()| file.sync_all())
                .map_err(|_| unavailable())?;
            signer
        } else {
            let metadata = fs::symlink_metadata(&path).map_err(|_| unavailable())?;
            if !metadata.is_file() || metadata.len() != 68 {
                return Err(unavailable());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(unavailable());
                }
            }
            let mut sealed = Vec::new();
            fs::File::open(&path)
                .map_err(|_| unavailable())?
                .take(69)
                .read_to_end(&mut sealed)
                .map_err(|_| unavailable())?;
            LocalSigner::open(id.clone(), &sealed, &unlock)?
        };
        let public = signer.public_jwk(&id)?;
        keys.insert(key_id, signer);
        Ok(public)
    })()
    .map_err(super::to_napi_error)?;
    serde_json::to_string(&result).map_err(|_| {
        Error::new(
            Status::GenericFailure,
            "public identity serialization failed",
        )
    })
}

pub fn sign(id: &KeyId, input: &[u8]) -> CoreResult<Option<Vec<u8>>> {
    keys()
        .lock()
        .map_err(|_| unavailable())?
        .get(id.as_str())
        .map(|key| key.sign(id, input))
        .transpose()
}
pub fn public_jwk(id: &str) -> CoreResult<Option<PublicJwk>> {
    keys()
        .lock()
        .map_err(|_| unavailable())?
        .get(id)
        .map(|key| key.public_jwk(&KeyId::new(id)))
        .transpose()
}
