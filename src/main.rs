mod api;
mod models;
mod node;
mod config;

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

    let node = Arc::new(Mutex::new(node::Node::new()));

    let server_handle = tokio::spawn(async move {
        api::start_server(node, Arc::new(tls_config), 3030).await
    });

    server_handle.await??;

    Ok(())
}
