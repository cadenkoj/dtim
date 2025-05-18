mod api;
mod config;
mod crypto;
mod logging;
mod models;
mod node;

use log::LevelFilter;
use models::{AccessScope, IndicatorType, ThreatIndicator};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use tokio::sync::Mutex;

fn init_logging() {
    env_logger::Builder::new()
        .filter_level(LevelFilter::Debug)
        .format_timestamp_millis()
        .init();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    init_logging();
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

    let crypto_context: crypto::CryptoContext =
        crypto::CryptoContext::new(config.security.key_rotation_days);

    let logger = logging::EncryptedLogger::new(
        config.storage.encrypted_logs_path.clone(),
        crypto_context.clone(),
        LevelFilter::Debug,
    )?;

    let node = node::Node::new(logger, config.privacy);

    let indicator = ThreatIndicator::new(
        IndicatorType::Ipv4Address,
        "127.0.0.1".to_string(),
        100,
        vec![],
        AccessScope::Private,
        None,
    );

    let encrypted = indicator.encrypt(&crypto_context);
    println!("Encrypted: {:?}", encrypted);

    let decrypted = ThreatIndicator::decrypt(&encrypted.unwrap(), &crypto_context);
    println!("Decrypted: {:?}", decrypted);

    let node = Arc::new(Mutex::new(node));
    let crypto_context = Arc::new(Mutex::new(crypto_context));

    {
        let mut node = node.lock().await;
        node.add_indicator(indicator.clone());
        node.bootstrap_peers(config.network.default_peers.clone());
    }

    let server_handle = tokio::spawn(async move {
        api::start_server(node, crypto_context, Arc::new(tls_config), 3030).await
    });

    server_handle.await??;

    Ok(())
}
