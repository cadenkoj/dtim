use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::Mutex;

mod api;
mod models;
mod node;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let indicator = models::ThreatIndicator::new(
        models::IndicatorType::Ipv4Address,
        "192.168.1.1".to_string(),
        100,
        1,
        vec!["test".to_string()]
    );

    let mut node = node::Node::new();
    node.bootstrap_peers(vec!["https://peer1.example.com:3030".to_string(), "https://peer2.example.com:3030".to_string()]);
    node.add_indicator(indicator.clone());

    let config = config::Config::builder();
    
    let config = config
        .set_override("tls_cert_path", "certs/server.crt")
        .expect("Failed to set cert path")
        .set_override("tls_key_path", "certs/server.key")
        .expect("Failed to set key path")
        .build()
        .expect("Failed to build config");

    let certs = CertificateDer::pem_file_iter(config.get::<String>("tls_cert_path").unwrap().clone())
        .expect("Failed to open certificate file")
        .map(|cert| cert.expect("Failed to parse certificate"))
        .collect();
    let private_key = PrivateKeyDer::from_pem_file(config.get::<String>("tls_key_path").unwrap().clone())
        .expect("Failed to parse private key");

    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .expect("Failed to build TLS config");

    let node = Arc::new(Mutex::new(node));
    let tls_config = Arc::new(tls_config);

    api::start_server(node, tls_config, 3030).await.unwrap();

    Ok(())
}
