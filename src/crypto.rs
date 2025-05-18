use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce, Key};
use base64::prelude::*;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct CryptoContext {
    current_key: Key<Aes256Gcm>,
    previous_key: Option<Key<Aes256Gcm>>,
    key_rotation_time: u64,
    rotation_interval: u64,
}

impl CryptoContext {
    pub fn new(rotation_days: u64) -> Self {
        let current_key = Self::generate_key();
        let key_rotation_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        CryptoContext {
            current_key,
            previous_key: None,
            key_rotation_time,
            rotation_interval: rotation_days * 24 * 60 * 60,
        }
    }

    pub fn set_key(&mut self, key: Key<Aes256Gcm>) {
        self.current_key = key;
    }

    pub fn rotate_key(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if now - self.key_rotation_time >= self.rotation_interval {
            self.previous_key = Some(self.current_key.clone());
            self.current_key = Self::generate_key();
            self.key_rotation_time = now;
        }
    }

    fn generate_key() -> Key<Aes256Gcm> {
        let mut key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut key_bytes);
        Key::<Aes256Gcm>::from_slice(&key_bytes).clone()
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(String, String, String), String> {
        let cipher = Aes256Gcm::new(&self.current_key);
        
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        match cipher.encrypt(nonce, plaintext) {
            Ok(mut ciphertext_and_tag) => {
                let tag = ciphertext_and_tag.split_off(ciphertext_and_tag.len() - 16);
                Ok((
                    BASE64_STANDARD.encode(ciphertext_and_tag),
                    BASE64_STANDARD.encode(nonce_bytes),
                    BASE64_STANDARD.encode(tag)
                ))
            }
            Err(_) => Err("Encryption failure".to_string())
        }
    }

    pub fn decrypt(&self, ciphertext_b64: &str, nonce_b64: &str, tag_b64: &str) -> Result<Vec<u8>, String> {
        let mut ciphertext = BASE64_STANDARD.decode(ciphertext_b64)
            .map_err(|_| "Invalid base64 ciphertext")?;
        let nonce_bytes = BASE64_STANDARD.decode(nonce_b64)
            .map_err(|_| "Invalid base64 nonce")?;
        let tag = BASE64_STANDARD.decode(tag_b64)
            .map_err(|_| "Invalid base64 tag")?;

        ciphertext.extend_from_slice(&tag);

        let nonce = Nonce::from_slice(&nonce_bytes);

        let try_decrypt = |key: &Key<Aes256Gcm>| {
            let cipher = Aes256Gcm::new(key);
            cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|_| "Decryption failed".to_string())
        };

        try_decrypt(&self.current_key).or_else(|_| {
            if let Some(prev_key) = &self.previous_key {
                try_decrypt(prev_key)
            } else {
                Err("Decryption failed and no previous key available".to_string())
            }
        })
    }
}
