mod keystore;
mod mesh_identity;
mod symmetric_key_manager;
mod tls_config;

use anyhow::Result;
pub use keystore::KeyStore;
pub use mesh_identity::{MeshIdentity, MeshIdentityManager};
use ring::aead;
pub use symmetric_key_manager::SymmetricKeyManager;
pub use tls_config::TlsManager;

use crate::errors::CryptoError;

#[derive(Clone, Debug)]
struct EncryptedData;

impl EncryptedData {
    pub fn concat(nonce: [u8; aead::NONCE_LEN], ciphertext_with_tag: Vec<u8>) -> Vec<u8> {
        let mut data = Vec::with_capacity(aead::NONCE_LEN + ciphertext_with_tag.len());
        data.extend_from_slice(&nonce);
        data.extend_from_slice(&ciphertext_with_tag);
        data
    }

    pub fn split(data: &[u8]) -> Result<(&[u8], &[u8])> {
        if data.len() < aead::NONCE_LEN + 16 {
            return Err(CryptoError::invalid_data("Invalid encrypted data length").into());
        }

        let nonce = &data[0..aead::NONCE_LEN];
        let ciphertext_with_tag = &data[aead::NONCE_LEN..];

        Ok((nonce, ciphertext_with_tag))
    }
}
