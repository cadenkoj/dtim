use std::sync::Arc;

use anyhow::Result;
use rustls::server::WebPkiClientVerifier;
use rustls::{
    pki_types::{pem::PemObject as _, CertificateDer, PrivateKeyDer},
    RootCertStore, ServerConfig,
};
use tokio::sync::Mutex;

use crate::errors::CryptoError;

use super::keystore::KeyStore;

pub struct TlsManager {
    keystore: Arc<Mutex<KeyStore>>,
}

impl TlsManager {
    pub fn new(keystore: Arc<Mutex<KeyStore>>) -> Self {
        Self { keystore }
    }

    pub async fn make_server_config(&self, require_client_auth: bool) -> Result<Arc<ServerConfig>> {
        let client_auth = if require_client_auth {
            let ca_certs = self.parse_certificates()?;

            let mut client_auth_roots = RootCertStore::empty();
            for cert in ca_certs {
                client_auth_roots
                    .add(cert)
                    .map_err(|e| CryptoError::invalid_key(format!("Invalid CA cert: {}", e)))?;
            }

            WebPkiClientVerifier::builder(client_auth_roots.into())
                .build()
                .map_err(|e| CryptoError::invalid_key(format!("Client verifier error: {}", e)))?
        } else {
            WebPkiClientVerifier::no_client_auth()
        };

        let certs = self.parse_certificates()?;
        let private_key = self.parse_private_key()?;

        let config = ServerConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .map_err(|e| CryptoError::invalid_key(format!("TLS config error: {}", e)))?
        .with_client_cert_verifier(client_auth)
        .with_single_cert(certs, private_key)
        .map_err(|e| CryptoError::invalid_key(format!("Certificate error: {}", e)))?;

        Ok(Arc::new(config))
    }

    fn parse_certificates(&self) -> Result<Vec<CertificateDer<'static>>> {
        Ok(CertificateDer::pem_file_iter("certs/node.crt")
            .expect("Failed to parse certificate")
            .map(|result| result.unwrap())
            .collect::<Vec<CertificateDer<'static>>>())
    }

    fn parse_private_key(&self) -> Result<PrivateKeyDer<'static>> {
        Ok(PrivateKeyDer::from_pem_file("certs/node.key")
            .map_err(|e| CryptoError::invalid_key(format!("Invalid private key: {}", e)))?)
    }

    pub async fn refresh_config(&self, require_client_auth: bool) -> Result<Arc<ServerConfig>> {
        {
            let mut keystore = self.keystore.lock().await;
            keystore.rotate_keys()?;
        }
        self.make_server_config(require_client_auth).await
    }
}
