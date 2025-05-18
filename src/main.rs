mod api;
mod config;
mod crypto;
mod models;
mod node;

use models::{IndicatorType, ThreatIndicator};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = config::Config::load()?;

    let certs = CertificateDer::pem_file_iter(config.security.tls_cert_path.clone())
        .expect("Failed to open certificate file")
        .map(|cert| cert.expect("Failed to parse certificate"))
        .collect();
    let private_key = PrivateKeyDer::from_pem_file(config.security.tls_key_path.clone())
        .expect("Failed to parse private key");

    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)?;

    let mut node = node::Node::new();
    let mut crypto_context: crypto::CryptoContext = crypto::CryptoContext::new(config.security.key_rotation_days);

    let key_bytes = [1u8; 32];
    let key = aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(&key_bytes).clone();
    crypto_context.set_key(key);

    let indicator = ThreatIndicator::new(
        IndicatorType::Ipv4Address,
        "127.0.0.1".to_string(),
        100,
        1,
        vec![],
    );

    node.add_indicator(indicator.clone());

    let encrypted = indicator.encrypt(&crypto_context);
    println!("Encrypted: {:?}", encrypted);

    let decrypted = ThreatIndicator::decrypt(&encrypted, &crypto_context);
    println!("Decrypted: {:?}", decrypted);

    let node = Arc::new(Mutex::new(node));
    let crypto_context = Arc::new(Mutex::new(crypto_context));
    let server_handle = tokio::spawn(async move {
        api::start_server(node, crypto_context, Arc::new(tls_config), 3030).await
    });

    server_handle.await??;

    Ok(())
}
