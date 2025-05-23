use ring::{aead, rand::SecureRandom as _};
use std::sync::Arc;
use tokio::sync::Mutex;

use anyhow::Result;

use crate::errors::CryptoError;

use super::{keystore::KeyStore, EncryptedData};

pub struct SymmetricKeyManager {
    keystore: Arc<Mutex<KeyStore>>,
    current_key: Arc<aead::LessSafeKey>,
    previous_keys: Vec<Arc<aead::LessSafeKey>>,
    rng: ring::rand::SystemRandom,
}

impl SymmetricKeyManager {
    pub async fn new(keystore: Arc<Mutex<KeyStore>>) -> Result<Self> {
        let keystore_guard = keystore.lock().await;
        let current_keys = keystore_guard.get_current_keys()?;
        let current_key = Self::create_aead_key(&current_keys.data_encryption_key)?;

        // Load previous keys for decryption fallback
        let mut previous_keys = Vec::new();
        let current_version = keystore_guard.get_current_version();

        for version in (current_version.saturating_sub(2)..current_version).rev() {
            if let Ok(key_version) = keystore_guard.get_keys_by_version(version) {
                if let Ok(key) = Self::create_aead_key(&key_version.data_encryption_key) {
                    previous_keys.push(Arc::new(key));
                }
            }
        }

        drop(keystore_guard);

        Ok(Self {
            keystore,
            current_key: Arc::new(current_key),
            previous_keys,
            rng: ring::rand::SystemRandom::new(),
        })
    }

    fn create_aead_key(key_bytes: &[u8; 32]) -> Result<aead::LessSafeKey> {
        let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, key_bytes)
            .map_err(|e| CryptoError::invalid_key(format!("Invalid key: {}", e)))?;
        Ok(aead::LessSafeKey::new(unbound_key))
    }

    pub async fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Check if rotation is needed and update keys if so
        {
            let mut keystore = self.keystore.lock().await;
            let old_version = keystore.get_current_version();
            keystore.rotate_keys()?;
            let new_version = keystore.get_current_version();

            if new_version != old_version {
                // Keys were rotated, update our cached keys
                let new_keys = keystore.get_current_keys()?;
                let new_aead_key = Self::create_aead_key(&new_keys.data_encryption_key)?;

                // Move current key to previous keys
                self.previous_keys.insert(0, self.current_key.clone());
                self.current_key = Arc::new(new_aead_key);
                self.previous_keys.truncate(2); // Keep only last 2 for decryption
            }
        }

        let mut nonce_bytes = [0u8; aead::NONCE_LEN];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| CryptoError::encryption_failed("Failed to generate nonce"))?;
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = plaintext.to_vec();
        self.current_key
            .seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)
            .map_err(|_| CryptoError::encryption_failed("AEAD seal failed"))?;

        Ok(EncryptedData::concat(nonce_bytes, in_out))
    }

    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        let (nonce_bytes, ciphertext_with_tag) = EncryptedData::split(encrypted)?;

        let nonce_array: [u8; aead::NONCE_LEN] = nonce_bytes
            .try_into()
            .map_err(|_| CryptoError::invalid_data("Invalid nonce length"))?;

        // Try current key first
        let mut data = ciphertext_with_tag.to_vec();
        if let Ok(plaintext) = self.current_key.open_in_place(
            aead::Nonce::assume_unique_for_key(nonce_array),
            aead::Aad::empty(),
            &mut data,
        ) {
            return Ok(plaintext.to_vec());
        }

        // Try previous keys
        for prev_key in &self.previous_keys {
            let mut data = ciphertext_with_tag.to_vec();
            if let Ok(plaintext) = prev_key.open_in_place(
                aead::Nonce::assume_unique_for_key(nonce_array),
                aead::Aad::empty(),
                &mut data,
            ) {
                return Ok(plaintext.to_vec());
            }
        }

        Err(CryptoError::DecryptionFailed.into())
    }

    // pub fn encrypt_batch(&mut self, plaintexts: &[&[u8]]) -> Result<Vec<Vec<u8>>> {
    //     self.rotate_key()?;

    //     let mut results = Vec::with_capacity(plaintexts.len());

    //     for plaintext in plaintexts {
    //         let mut nonce_bytes = [0u8; NONCE_LEN];
    //         self.rng
    //             .fill(&mut nonce_bytes)
    //             .map_err(|_| std::io::Error::other("Failed to generate nonce"))?;
    //         let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    //         let mut in_out = plaintext.to_vec();
    //         self.current_key
    //             .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
    //             .map_err(|_| std::io::Error::other("Failed to encrypt"))?;

    //         results.push(EncryptedData::concat(nonce_bytes, in_out));
    //     }

    //     Ok(results)
    // }

    pub fn decrypt_batch_par(&self, encrypted_data: &[Vec<u8>]) -> Vec<Result<Vec<u8>>> {
        use rayon::prelude::*;

        let chunk_size = if encrypted_data.len() > 1000 {
            (encrypted_data.len() / rayon::current_num_threads()).max(50)
        } else {
            100
        };

        encrypted_data
            .par_chunks(chunk_size)
            .flat_map(|chunk| {
                chunk
                    .iter()
                    .map(|encrypted| self.decrypt(encrypted))
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}
