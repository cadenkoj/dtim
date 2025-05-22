use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const SYMM_KEY_PATH: &str = "data/keys/symm.key";
const SYMM_PREV_KEY_PATH: &str = "data/keys/symm_prev.key";

pub type EncryptedData = (Vec<u8>, Vec<u8>, Vec<u8>);

#[derive(Clone, Debug)]
pub struct SymmetricKeyManager {
    current_key: Key<Aes256Gcm>,
    previous_key: Option<Key<Aes256Gcm>>,
    key_rotation_time: u64,
    rotation_interval: u64,
}

impl SymmetricKeyManager {
    pub fn load_or_generate(rotation_days: u64) -> std::io::Result<Self> {
        fs::create_dir_all("data/keys")?;

        let mut current_bytes = [0u8; 32];
        let mut prev_bytes = [0u8; 32];

        let current_key = if Path::new(SYMM_KEY_PATH).exists() {
            File::open(SYMM_KEY_PATH)?.read_exact(&mut current_bytes)?;
            Key::<Aes256Gcm>::from_slice(&current_bytes).to_owned()
        } else {
            let key = Self::generate_key();
            let mut file = File::create(SYMM_KEY_PATH)?;
            file.write_all(key.as_slice())?;
            key
        };

        let previous_key = if Path::new(SYMM_PREV_KEY_PATH).exists() {
            File::open(SYMM_PREV_KEY_PATH)?.read_exact(&mut prev_bytes)?;
            Some(Key::<Aes256Gcm>::from_slice(&prev_bytes).to_owned())
        } else {
            None
        };

        let key_rotation_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(Self {
            current_key,
            previous_key,
            key_rotation_time,
            rotation_interval: rotation_days * 24 * 60 * 60,
        })
    }

    fn generate_key() -> Key<Aes256Gcm> {
        let mut key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut key_bytes);
        Key::<Aes256Gcm>::from_slice(&key_bytes).to_owned()
    }

    pub fn save_keys(&self) -> std::io::Result<()> {
        fs::create_dir_all("data/keys")?;
        let mut file = File::create(SYMM_KEY_PATH)?;
        file.write_all(self.current_key.as_slice())?;

        if let Some(prev) = &self.previous_key {
            let mut prev_file = File::create(SYMM_PREV_KEY_PATH)?;
            prev_file.write_all(prev.as_slice())?;
        } else if Path::new(SYMM_PREV_KEY_PATH).exists() {
            fs::remove_file(SYMM_PREV_KEY_PATH)?;
        }
        Ok(())
    }

    pub fn rotate_key(&mut self) -> std::io::Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now - self.key_rotation_time >= self.rotation_interval {
            self.previous_key = Some(self.current_key);
            self.current_key = Self::generate_key();
            self.key_rotation_time = now;
            self.save_keys()?;
        }
        Ok(())
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<EncryptedData, std::io::Error> {
        self.rotate_key()?;
        let cipher = Aes256Gcm::new(&self.current_key);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        match cipher.encrypt(nonce, plaintext) {
            Ok(mut ciphertext_and_tag) => {
                let tag = ciphertext_and_tag.split_off(ciphertext_and_tag.len() - 16);
                Ok((ciphertext_and_tag, nonce_bytes.to_vec(), tag))
            }
            Err(_) => Err(std::io::Error::other("Encryption failure")),
        }
    }

    pub fn decrypt(
        &self,
        mut ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        tag: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        ciphertext.extend_from_slice(&tag);
        let nonce = Nonce::from_slice(&nonce);
        let try_decrypt = |key: &Key<Aes256Gcm>| {
            let cipher = Aes256Gcm::new(key);
            cipher
                .decrypt(nonce, ciphertext.as_ref())
                .map_err(|_| "Decryption failed".to_string())
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
