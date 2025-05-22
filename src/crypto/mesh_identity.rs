use aes_gcm::aead::OsRng;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest as _, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

pub const PRIVATE_KEY_PATH: &str = "data/keys/mesh.key";
pub const PUBLIC_KEY_PATH: &str = "data/keys/mesh.pub";

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

impl MeshIdentity {
    pub fn load_or_generate() -> std::io::Result<Self> {
        if !Path::new(PRIVATE_KEY_PATH).exists() || !Path::new(PUBLIC_KEY_PATH).exists() {
            Self::generate_and_save()?;
        }
        let mut priv_bytes = [0u8; ed25519_dalek::SECRET_KEY_LENGTH];
        let mut pub_bytes = [0u8; ed25519_dalek::PUBLIC_KEY_LENGTH];
        File::open(PRIVATE_KEY_PATH)?.read_exact(&mut priv_bytes)?;
        File::open(PUBLIC_KEY_PATH)?.read_exact(&mut pub_bytes)?;
        let signing_key = SigningKey::from_bytes(&priv_bytes);
        let verifying_key = VerifyingKey::from_bytes(&pub_bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(Self::Local {
            id: MeshIdentity::derive_hex_id(&pub_bytes),
            signing_key: Box::new(signing_key),
            verifying_key: Box::new(verifying_key),
        })
    }

    pub fn generate_and_save() -> std::io::Result<()> {
        if let Some(parent) = Path::new(PRIVATE_KEY_PATH).parent() {
            fs::create_dir_all(parent)?;
        }
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        let mut priv_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(PRIVATE_KEY_PATH)?;
        let mut pub_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(PUBLIC_KEY_PATH)?;
        priv_file.write_all(&signing_key.to_bytes())?;
        pub_file.write_all(&verifying_key.to_bytes())?;
        Ok(())
    }

    pub fn sign(signing_key: SigningKey, message: &[u8]) -> String {
        let sig = signing_key.sign(message);
        BASE64_STANDARD.encode(sig.to_bytes())
    }

    pub fn verify(verifying_key: VerifyingKey, message: &[u8], signature_b64: &str) -> bool {
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
}
