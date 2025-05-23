use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest as _, Sha256};
use std::sync::Arc;
use tokio::sync::Mutex;

use super::keystore::KeyStore;
use crate::errors::CryptoError;

#[derive(Clone, Debug)]
pub enum MeshIdentity {
    Local {
        id: String,
        verifying_key: Box<VerifyingKey>,
        signing_key: Box<SigningKey>,
    },
    Remote {
        id: String,
        verifying_key: Box<VerifyingKey>,
    },
}

#[derive(Clone)]
pub struct MeshIdentityManager {
    keystore: Arc<Mutex<KeyStore>>,
    current_identity: MeshIdentity,
}

impl MeshIdentityManager {
    pub async fn new(keystore: Arc<Mutex<KeyStore>>) -> Result<Self> {
        let keystore_guard = keystore.lock().await;
        let current_keys = keystore_guard.get_current_keys()?;

        let signing_key = SigningKey::from_bytes(&current_keys.mesh_signing_key);
        let verifying_key = VerifyingKey::from_bytes(&current_keys.mesh_verifying_key)
            .map_err(|e| CryptoError::invalid_key(format!("Invalid verifying key: {}", e)))?;

        let id = Self::derive_hex_id(&current_keys.mesh_verifying_key);

        let current_identity = MeshIdentity::Local {
            id,
            verifying_key: Box::new(verifying_key),
            signing_key: Box::new(signing_key),
        };

        drop(keystore_guard);

        Ok(Self {
            keystore,
            current_identity,
        })
    }

    pub fn get_identity(&self) -> &MeshIdentity {
        &self.current_identity
    }

    pub async fn refresh_identity(&mut self) -> Result<()> {
        let keystore_guard = self.keystore.lock().await;
        let current_keys = keystore_guard.get_current_keys()?;

        let signing_key = SigningKey::from_bytes(&current_keys.mesh_signing_key);
        let verifying_key = VerifyingKey::from_bytes(&current_keys.mesh_verifying_key)
            .map_err(|e| CryptoError::invalid_key(format!("Invalid verifying key: {}", e)))?;

        let id = Self::derive_hex_id(&current_keys.mesh_verifying_key);

        self.current_identity = MeshIdentity::Local {
            id,
            verifying_key: Box::new(verifying_key),
            signing_key: Box::new(signing_key),
        };

        Ok(())
    }

    pub fn sign(&self, message: &[u8]) -> Result<String> {
        match &self.current_identity {
            MeshIdentity::Local { signing_key, .. } => {
                let sig = signing_key.sign(message);
                Ok(BASE64_STANDARD.encode(sig.to_bytes()))
            }
            MeshIdentity::Remote { .. } => {
                Err(CryptoError::invalid_key("Cannot sign with remote identity").into())
            }
        }
    }

    pub fn verify(&self, message: &[u8], signature_b64: &str) -> bool {
        let verifying_key = match &self.current_identity {
            MeshIdentity::Local { verifying_key, .. } => verifying_key,
            MeshIdentity::Remote { verifying_key, .. } => verifying_key,
        };

        Self::verify_with_key(verifying_key, message, signature_b64)
    }

    pub fn verify_with_key(
        verifying_key: &VerifyingKey,
        message: &[u8],
        signature_b64: &str,
    ) -> bool {
        let sig_bytes: Vec<u8> = match BASE64_STANDARD.decode(signature_b64) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let sig_array: &[u8; 64] = match sig_bytes.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => return false,
        };

        let sig = Signature::from_bytes(sig_array);
        verifying_key.verify(message, &sig).is_ok()
    }

    pub fn derive_hex_id(pubkey_bytes: &[u8; 32]) -> String {
        let hash = Sha256::digest(pubkey_bytes);
        hex::encode(hash)
    }

    pub fn create_remote_identity(verifying_key_bytes: &[u8; 32]) -> Result<MeshIdentity> {
        let verifying_key = VerifyingKey::from_bytes(verifying_key_bytes)
            .map_err(|e| CryptoError::invalid_key(format!("Invalid verifying key: {}", e)))?;

        let id = Self::derive_hex_id(verifying_key_bytes);

        Ok(MeshIdentity::Remote {
            id,
            verifying_key: Box::new(verifying_key),
        })
    }
}

impl MeshIdentity {
    pub fn id(&self) -> &String {
        match self {
            Self::Local { id, .. } => id,
            Self::Remote { id, .. } => id,
        }
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        match self {
            Self::Local { verifying_key, .. } => verifying_key,
            Self::Remote { verifying_key, .. } => verifying_key,
        }
    }

    pub fn signing_key(&self) -> Option<&SigningKey> {
        match self {
            Self::Local { signing_key, .. } => Some(signing_key),
            Self::Remote { .. } => None,
        }
    }

    pub fn is_local(&self) -> bool {
        matches!(self, Self::Local { .. })
    }

    pub fn is_remote(&self) -> bool {
        matches!(self, Self::Remote { .. })
    }
}
