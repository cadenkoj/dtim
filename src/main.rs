mod api;
mod crypto;
mod db;
mod error;
mod logging;
mod models;
mod node;
mod settings;
mod uuid;

use axum::body::Body;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use crypto::MeshIdentity;
use http_body_util::BodyExt as _;
use log::LevelFilter;
use models::{IndicatorType, ThreatIndicator};
use node::NodePeer;
use rustls::crypto::aws_lc_rs as provider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use serde_json::json;
use settings::Settings;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;

fn init_logging() {
    env_logger::Builder::new()
        .filter_level(LevelFilter::Debug)
        .format_timestamp_millis()
        .init();
}

fn load_certs(filename: &Path) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_file_iter(filename)
        .expect("cannot open certificate file")
        .map(|result| result.unwrap())
        .collect()
}

fn load_private_key(filename: &Path) -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_file(filename).expect("cannot read private key file")
}

fn make_server_config(settings: &settings::Settings) -> Arc<rustls::ServerConfig> {
    let client_auth = if let Some(auth) = &settings.tls.ca {
        let roots = load_certs(auth);
        let mut client_auth_roots = RootCertStore::empty();
        for root in roots {
            client_auth_roots.add(root).unwrap();
        }
        WebPkiClientVerifier::builder(client_auth_roots.into())
            .build()
            .unwrap()
    } else {
        WebPkiClientVerifier::no_client_auth()
    };

    let certs = load_certs(&settings.tls.certs);
    let privkey = load_private_key(&settings.tls.key);

    let config = rustls::ServerConfig::builder_with_provider(provider::default_provider().into())
        .with_safe_default_protocol_versions()
        .expect("inconsistent cipher-suites/versions specified")
        .with_client_cert_verifier(client_auth)
        .with_single_cert(certs, privkey)
        .expect("bad certificates/private key");

    Arc::new(config)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    init_logging();
    let settings = Settings::new()?;
    let mut key_mgr =
        crypto::SymmetricKeyManager::load_or_generate(settings.tls.key_rotation_days)?;
    let tls_config = make_server_config(&settings);

    let logger = logging::EncryptedLogger::new(
        settings.storage.encrypted_logs_path.clone(),
        key_mgr.clone(),
        LevelFilter::from_str(&settings.log_level).unwrap_or_else(|_| {
            log::warn!(
                "Invalid log level: {}, defaulting to Info",
                settings.log_level
            );
            LevelFilter::Info
        }),
    )?;

    println!("Database URL: {:?}", settings.storage.database_url);
    let db_pool = db::get_connection_pool(&settings.storage.database_url)?;
    let node = node::Node::new(db_pool, key_mgr.clone(), logger, settings.privacy)?;

    let id = node.get_id();
    println!("Node ID: {:?}", id);

    let base64_pubkey = BASE64_STANDARD.encode(node.identity().verifying_key().to_bytes());

    let mut data = NodePeer {
        id: id.to_string(),
        endpoint: "127.0.0.1:3030".to_string(),
        public_key: base64_pubkey,
        signature: None,
    };

    let body = Body::from(serde_json::to_string(&data).unwrap());

    let bytes = body
        .collect()
        .await
        .expect("Failed to collect body")
        .to_bytes();

    let signing_key = node
        .identity()
        .signing_key()
        .ok_or_else(|| std::io::Error::other("Failed to get signing key".to_string()))?;
    let signature = MeshIdentity::sign(signing_key.clone(), &bytes);

    data.set_signature(signature);

    println!("{}", json!(data));

    let indicator = ThreatIndicator::new(
        IndicatorType::Ipv4Address,
        "127.0.0.1".to_string(),
        100,
        vec!["malicious-activity".to_string()],
        models::TlpLevel::White,
        None,
    )
    .unwrap();

    let encrypted = indicator.encrypt(&mut key_mgr).unwrap();
    println!(
        "Encrypted: {:?}",
        serde_json::to_string(&encrypted).unwrap()
    );

    let _ = key_mgr.rotate_key();

    let decrypted = ThreatIndicator::decrypt(&encrypted, &key_mgr).unwrap();
    println!("Decrypted: {:?}", decrypted);

    let node = Arc::new(Mutex::new(node));

    {
        let mut node = node.lock().await;
        let _ = node.add_or_increment_indicator(indicator.clone());
        node.bootstrap_peers(settings.network.init_peers.clone());
    }

    let server_handle = tokio::spawn(async move {
        api::start_server(node, key_mgr, tls_config, settings.address, settings.port).await
    });

    server_handle.await??;

    Ok(())
}
