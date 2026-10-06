//! Encrypted POC signing identity. Storage and unlock-key delivery belong to the runtime.
use crate::{CoreError, CoreErrorCode, CoreResult, KeyId, KeyStore, PublicJwk, Signer};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use zeroize::Zeroizing;

/// Private signing material is never exported from this handle.
pub struct LocalSigner {
    key_id: KeyId,
    key: SigningKey,
}

impl LocalSigner {
    pub fn generate(key_id: KeyId) -> CoreResult<Self> {
        Ok(Self {
            key_id,
            key: SigningKey::from(crate::random_p256_secret()?),
        })
    }

    pub fn seal(&self, unlock: &[u8]) -> CoreResult<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(unlock).map_err(|_| invalid())?;
        let mut nonce = [0_u8; 12];
        getrandom::fill(&mut nonce).map_err(|_| invalid())?;
        let private = Zeroizing::new(self.key.to_bytes());
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: private.as_slice(),
                    aad: self.key_id.as_str().as_bytes(),
                },
            )
            .map_err(|_| invalid())?;
        Ok([b"VCKey001".as_slice(), &nonce, &ciphertext].concat())
    }

    pub fn open(key_id: KeyId, sealed: &[u8], unlock: &[u8]) -> CoreResult<Self> {
        if sealed.len() != 68 || &sealed[..8] != b"VCKey001" {
            return Err(invalid());
        }
        let cipher = Aes256Gcm::new_from_slice(unlock).map_err(|_| invalid())?;
        let private = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&sealed[8..20]),
                    Payload {
                        msg: &sealed[20..],
                        aad: key_id.as_str().as_bytes(),
                    },
                )
                .map_err(|_| invalid())?,
        );
        let key = SigningKey::from_slice(&private).map_err(|_| invalid())?;
        Ok(Self { key_id, key })
    }
}

fn invalid() -> CoreError {
    CoreError::new(
        CoreErrorCode::InvalidKey,
        "persistent signing identity unavailable or locked",
    )
}

impl Signer for LocalSigner {
    fn sign(&self, key_id: &KeyId, input: &[u8]) -> CoreResult<Vec<u8>> {
        if key_id != &self.key_id {
            return Err(invalid());
        }
        let signature: Signature = self.key.sign(input);
        Ok(signature.to_bytes().to_vec())
    }
}
impl KeyStore for LocalSigner {
    fn public_jwk(&self, key_id: &KeyId) -> CoreResult<PublicJwk> {
        if key_id != &self.key_id {
            return Err(invalid());
        }
        let point = self.key.verifying_key().to_sec1_point(false);
        Ok(PublicJwk::p256(
            crate::b64_encode(point.x().ok_or_else(invalid)?),
            crate::b64_encode(point.y().ok_or_else(invalid)?),
            Some(key_id.as_str().to_owned()),
        ))
    }
}
