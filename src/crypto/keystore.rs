use ::rand::rngs::OsRng;
use anyhow::Result;
use bincode::{Decode, Encode};
use directories::ProjectDirs;
use ring::rand::SecureRandom as _;
use ring::{aead, hkdf, rand};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Write};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::CryptoError;

use super::EncryptedData;

const CURRENT_SCHEMA_VERSION: u32 = 1;
const KEYSTORE_FILENAME: &str = "keystore.json";
const TEMP_SUFFIX: &str = ".tmp";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VersionedKeyStore {
    schema_version: u32,
    current_version: u32,
    versions: BTreeMap<u32, EncryptedKeyVersion>,
    created_at: u64,
    last_rotation: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncryptedKeyVersion {
    version: u32,
    created_at: u64,
    data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop, Encode, Decode)]
pub struct KeyVersion {
    pub version: u32,
    pub created_at: u64,

    pub mesh_signing_key: [u8; ed25519_dalek::SECRET_KEY_LENGTH],
    pub mesh_verifying_key: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH],

    pub data_encryption_key: [u8; 32],
}

#[derive(Debug)]
pub struct KeyStore {
    key_dir: PathBuf,
    store: VersionedKeyStore,
    rotation_interval: u64,
}

impl KeyStore {
    pub fn load_or_generate(org: &str, rotation_days: u64) -> Result<Self> {
        let key_dir = get_key_directory(org)?;
        let keystore_path = key_dir.join(KEYSTORE_FILENAME);

        let store = if keystore_path.exists() {
            println!("Loading keystore from {}", keystore_path.display());
            Self::load_keystore(&keystore_path)?
        } else {
            println!("Creating new keystore at {}", keystore_path.display());
            Self::create_new_keystore()?
        };

        let instance = Self {
            key_dir,
            store,
            rotation_interval: rotation_days * 24 * 60 * 60,
        };

        instance.save_keystore()?;
        Ok(instance)
    }

    fn load_keystore(keystore_path: &PathBuf) -> Result<VersionedKeyStore> {
        let file = File::open(keystore_path)?;
        let reader = BufReader::new(file);
        let store: VersionedKeyStore = serde_json::from_reader(reader)?;
        Ok(store)
    }

    fn create_new_keystore() -> Result<VersionedKeyStore> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let initial_keys = Self::generate_key_version(1, now)?;
        let encrypted_version = Self::encrypt_key_version(&initial_keys)?;

        let mut versions = BTreeMap::new();
        versions.insert(1, encrypted_version);

        Ok(VersionedKeyStore {
            schema_version: CURRENT_SCHEMA_VERSION,
            current_version: 1,
            versions,
            created_at: now,
            last_rotation: now,
        })
    }

    fn generate_key_version(version: u32, timestamp: u64) -> Result<KeyVersion> {
        let rng = rand::SystemRandom::new();

        // Generate symmetric key
        let mut data_encryption_key = [0u8; 32];
        rng.fill(&mut data_encryption_key)
            .map_err(|e| CryptoError::KeyDerivation {
                reason: format!("Failed to fill data encryption key: {}", e),
            })?;

        // Generate mesh identity keys
        let mut csprng = OsRng;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        Ok(KeyVersion {
            version,
            created_at: timestamp,
            mesh_signing_key: signing_key.to_bytes(),
            mesh_verifying_key: verifying_key.to_bytes(),
            data_encryption_key,
        })
    }


    fn derive_master_key() -> Result<[u8; 32]> {
        let hostname = hostname::get()
            .map_err(|e| CryptoError::KeyDerivation {
                reason: format!("Failed to get hostname: {}", e),
            })?
            .to_string_lossy()
            .to_string();

        let machine_id = fs::read_to_string("/etc/machine-id")
            .or_else(|_| fs::read_to_string("/var/lib/dbus/machine-id"))
            .or_else(|_| std::env::var("HOSTNAME"))
            .map_err(|e| CryptoError::KeyDerivation {
                reason: format!("Failed to get machine ID: {}", e),
            })?;

        let combined = format!("{}:{}", hostname.trim(), machine_id.trim());

        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"keystore-master-key-v1");
        let prk = salt.extract(combined.as_bytes());

        let mut master_key = [0u8; 32];
        prk.expand(&[b"aes-256-gcm-key"], hkdf::HKDF_SHA256)
            .map_err(|e| CryptoError::KeyDerivation {
                reason: format!("Failed to expand master key: {}", e),
            })?
            .fill(&mut master_key)
            .map_err(|e| CryptoError::KeyDerivation {
                reason: format!("Failed to fill master key: {}", e),
            })?;

        println!("Master key: {:?}", master_key);

        Ok(master_key)
    }

    fn encrypt_key_version(keys: &KeyVersion) -> Result<EncryptedKeyVersion> {
        let master_key = Self::derive_master_key()?;
        let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &master_key).map_err(|e| {
            CryptoError::KeyDerivation {
                reason: format!("Failed to create unbound key: {}", e),
            }
        })?;
        let key = aead::LessSafeKey::new(unbound_key);

        let mut nonce_bytes = [0u8; 12];
        let rng = rand::SystemRandom::new();
        rng.fill(&mut nonce_bytes)
            .map_err(|e| CryptoError::KeyDerivation {
                reason: format!("Failed to fill nonce bytes: {}", e),
            })?;

        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
        let mut ciphertext = bincode::encode_to_vec(keys, bincode::config::standard())?;

        key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut ciphertext)
            .map_err(|e| CryptoError::EncryptionFailed {
                reason: format!("Failed to seal key version: {}", e),
            })?;

        Ok(EncryptedKeyVersion {
            version: keys.version,
            created_at: keys.created_at,
            data: EncryptedData::concat(nonce_bytes, ciphertext),
        })
    }

    fn decrypt_key_version(encrypted: &EncryptedKeyVersion) -> Result<KeyVersion> {
        let master_key = Self::derive_master_key()?;
        let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &master_key).map_err(|e| {
            CryptoError::KeyDerivation {
                reason: format!("Failed to create unbound key: {}", e),
            }
        })?;
        let key = aead::LessSafeKey::new(unbound_key);

        let (nonce_bytes, ciphertext_with_tag) = EncryptedData::split(&encrypted.data)?;
        let nonce_array: [u8; aead::NONCE_LEN] = nonce_bytes
            .try_into()
            .map_err(|_| CryptoError::invalid_data("Invalid nonce length"))?;
        let nonce = aead::Nonce::assume_unique_for_key(nonce_array);

        let mut data = ciphertext_with_tag.to_vec();
        let decrypted = key
            .open_in_place(nonce, aead::Aad::empty(), &mut data)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        let keys: KeyVersion = bincode::decode_from_slice(decrypted, bincode::config::standard())
            .map_err(|e| CryptoError::KeyDerivation {
                reason: format!("Failed to deserialize key version: {}", e),
            })?
            .0;
        Ok(keys)
    }

    fn save_keystore(&self) -> Result<()> {
        let keystore_path = self.key_dir.join(KEYSTORE_FILENAME);
        let temp_path = self
            .key_dir
            .join(format!("{}{}", KEYSTORE_FILENAME, TEMP_SUFFIX));

        let json = serde_json::to_string_pretty(&self.store)?;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp_path)?;

        file.write_all(json.as_bytes())?;
        file.sync_all()?;
        drop(file);

        fs::rename(temp_path, keystore_path)?;
        Ok(())
    }

    pub fn rotate_keys(&mut self) -> Result<u32> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if now - self.store.last_rotation < self.rotation_interval {
            return Ok(self.store.current_version);
        }

        let new_version = self.store.current_version + 1;
        log::info!("Rotating keys to version {}", new_version);

        let new_keys = Self::generate_key_version(new_version, now)?;
        let encrypted_version = Self::encrypt_key_version(&new_keys)?;

        self.store.versions.insert(new_version, encrypted_version);
        self.store.current_version = new_version;
        self.store.last_rotation = now;

        let min_version = new_version.saturating_sub(4);
        self.store.versions.retain(|&v, _| v >= min_version);

        self.save_keystore()?;

        log::info!("Key rotation completed to version {}", new_version);
        Ok(new_version)
    }

    pub fn get_current_keys(&self) -> Result<KeyVersion> {
        self.get_keys_by_version(self.store.current_version)
    }

    pub fn get_keys_by_version(&self, version: u32) -> Result<KeyVersion> {
        let encrypted = self
            .store
            .versions
            .get(&version)
            .ok_or_else(|| CryptoError::VersionNotFound { version })?;
        Self::decrypt_key_version(encrypted)
    }

    pub fn get_current_version(&self) -> u32 {
        self.store.current_version
    }

    pub fn force_rotation(&mut self) -> Result<u32> {
        let original_last_rotation = self.store.last_rotation;
        self.store.last_rotation = 0;

        let result = self.rotate_keys();

        if result.is_err() {
            self.store.last_rotation = original_last_rotation;
        }

        result
    }
}

fn get_key_directory(org: &str) -> Result<PathBuf> {
    if let Some(proj_dirs) = ProjectDirs::from("com", org, "dtim") {
        let key_dir = proj_dirs.data_dir().join("keys");
        std::fs::create_dir_all(&key_dir)?;
        Ok(key_dir)
    } else {
        let key_dir = PathBuf::from("data/keys");
        std::fs::create_dir_all(&key_dir)?;
        Ok(key_dir)
    }
}
