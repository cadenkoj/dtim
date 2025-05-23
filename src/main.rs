mod api;
mod crypto;
mod db;
mod errors;
// mod logging;
mod metrics;
mod models;
mod node;
mod settings;
mod uuid;

use anyhow::Result;
use axum::body::Body;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use crypto::{KeyStore, MeshIdentityManager, SymmetricKeyManager, TlsManager};
use http_body_util::BodyExt as _;
use log::LevelFilter;
use models::{IndicatorType, ThreatIndicator};
use node::NodePeer;
use serde_json::json;
use settings::Settings;
use std::{str::FromStr, sync::Arc};
use tokio::sync::Mutex;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

// fn init_logging() {
//     env_logger::Builder::new()
//         .filter_level(LevelFilter::Debug)
//         .format_timestamp_millis()
//         .init();
// }

#[tokio::main]
async fn main() -> Result<()> {
    // init_logging();
    let settings = Settings::new()?;

    let mut keystore = KeyStore::load_or_generate(&settings.org, settings.tls.key_rotation_days)?;
    keystore.force_rotation()?;
    let keystore = Arc::new(Mutex::new(keystore));

    println!("Keystore: {:?}", keystore);

    let symmetric_key_mgr = SymmetricKeyManager::new(keystore.clone()).await?;
    let mesh_identity_mgr = MeshIdentityManager::new(keystore.clone()).await?;
    let tls_mgr = TlsManager::new(keystore.clone());
    let tls_config = tls_mgr
        .make_server_config(settings.tls.ca.is_some())
        .await?;

    let symmetric_key_mgr = Arc::new(Mutex::new(symmetric_key_mgr));
    let mesh_identity_mgr = Arc::new(Mutex::new(mesh_identity_mgr));

    // let logger = logging::EncryptedLogger::new(
    //     settings.storage.encrypted_logs_path.clone(),
    //     symmetric_key_mgr,
    //     LevelFilter::from_str(&settings.log_level).unwrap_or_else(|_| {
    //         log::warn!(
    //             "Invalid log level: {}, defaulting to Info",
    //             settings.log_level
    //         );
    //         LevelFilter::Info
    //     }),
    // )?;

    println!("Database URL: {:?}", settings.storage.database_url);
    let db_pool = db::get_connection_pool(&settings.storage.database_url)?;
    let node = node::Node::new(
        db_pool,
        symmetric_key_mgr.clone(),
        mesh_identity_mgr.clone(),
        settings.privacy,
    )
    .await?;

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

    let mgr = mesh_identity_mgr.clone();
    let mgr = mgr.lock().await;
    let signature = mgr.sign(&bytes).unwrap();
    drop(mgr);

    data.set_signature(signature);

    println!("{}", json!(data));

    let indicator = ThreatIndicator::new(
        IndicatorType::Ipv4Address,
        "12117.0.0.1".to_string(),
        100,
        vec!["malicious-activity".to_string()].into_iter().collect(),
        models::TlpLevel::White,
        None,
    )
    .unwrap();

    // perf_monitor.measure_operation("jsonify_indicator", || {
    //     let data = indicator.to_stix(PrivacyLevel::Open, true).unwrap();
    //     println!("*** {}", data);
    // });

    // perf_monitor.measure_operation("jsonify_indicator_fast", || {
    //     let data = indicator.to_stix_fast(PrivacyLevel::Open, true).unwrap();
    //     println!("*** {}", data);
    // });

    // let encrypted = indicator.encrypt(&mut key_mgr).unwrap();
    // println!(
    //     "Encrypted: {:?}",
    //     serde_json::to_string(&encrypted).unwrap()
    // );

    // let _ = symmetric_key_mgr.rotate_key();

    // let decrypted = ThreatIndicator::decrypt(&encrypted, &key_mgr).unwrap();
    // println!("Decrypted: {:?}", decrypted);

    let node = Arc::new(Mutex::new(node));

    {
        let mut node = node.lock().await;
        let _ = node.add_or_increment_indicator(indicator.clone());
        node.bootstrap_peers(settings.network.init_peers.clone());
        for i in 0..1000 {
            let indicator = ThreatIndicator::new(
                IndicatorType::Ipv4Address,
                format!("{}", i),
                100,
                vec!["malicious-activity".to_string()].into_iter().collect(),
                models::TlpLevel::White,
                None,
            )
            .unwrap();
            node.add_or_increment_indicator(indicator.clone())
                .await
                .unwrap();
        }
    }

    let server_handle = tokio::spawn(async move {
        api::start_server(
            node,
            symmetric_key_mgr,
            mesh_identity_mgr,
            tls_config,
            settings.address,
            settings.port,
        )
        .await
    });

    println!("Server handle: {:?}", server_handle);

    server_handle.await?.map_err(|e| println!("Error: {:?}", e));

    Ok(())
}
