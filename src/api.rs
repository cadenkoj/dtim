use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    routing::{get, post},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use rustls::ServerConfig;
use serde::Serialize;
use std::sync::Arc;
use std::{io, str::FromStr};
use tokio::sync::Mutex;

use crate::node::Node;
use crate::{crypto::CryptoContext, models::StixBundle};
use crate::{
    models::{EncryptedThreatIndicator, ThreatIndicator},
    uuid::Uuid,
};

#[derive(Serialize)]
struct ApiError {
    error: String,
}

type ApiResponse<T> = Result<(StatusCode, Json<T>), (StatusCode, Json<ApiError>)>;

pub async fn start_server(
    node: Arc<Mutex<Node>>,
    crypto_context: Arc<Mutex<CryptoContext>>,
    config: Arc<ServerConfig>,
    port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Router::new()
        // Peer registry endpoints
        .route("/api/v1/nodes/register", post(register_node_handler))
        .route("/api/v1/peers", get(get_peers_handler))
        // Indicator endpoints
        .route("/api/v1/indicators/gossip", post(gossip_indicators_handler))
        .route(
            "/api/v1/indicators/public",
            get(get_public_indicators_handler),
        )
        .route(
            "/api/v1/indicators/private",
            get(get_private_indicators_handler),
        )
        .route("/api/v1/indicators/{id}", get(get_indicator_by_id_handler))
        // Log endpoint
        .route("/api/v1/logs/{date}", get(read_logs_handler))
        // TAXII endpoints (minimal)
        .route("/taxii2/", get(taxii_discovery_handler))
        .route("/taxii2/root/", get(taxii_api_root_handler))
        .route("/taxii2/root/collections/", get(taxii_collections_handler))
        .route(
            "/taxii2/root/collections/{id}/objects/",
            get(taxii_get_objects_handler),
        )
        .route(
            "/taxii2/root/collections/{id}/objects/",
            post(taxii_post_objects_handler),
        )
        .with_state((node, crypto_context));

    let addr = format!("0.0.0.0:{}", port).parse()?;
    let tls_config = RustlsConfig::from_config(config);
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to start server: {}", e),
            )
        })?;

    Ok(())
}

// --- Peer Registry Handlers ---

async fn register_node_handler(
    State((_, _)): State<(Arc<Mutex<Node>>, Arc<Mutex<CryptoContext>>)>,
    Json(_): Json<serde_json::Value>,
) -> ApiResponse<serde_json::Value> {
    // TODO: Implement node registration logic
    Ok((StatusCode::OK, Json(serde_json::json!({"status": "ok"}))))
}

async fn get_peers_handler(
    State((node, _)): State<(Arc<Mutex<Node>>, Arc<Mutex<CryptoContext>>)>,
) -> ApiResponse<Vec<serde_json::Value>> {
    // TODO: Implement peer list retrieval
    let node = node.lock().await;
    Ok((
        StatusCode::OK,
        Json(
            node.get_peers()
                .iter()
                .map(|p| serde_json::json!(p))
                .collect(),
        ),
    ))
}

// --- Indicator Handlers ---

async fn gossip_indicators_handler(
    State((node, crypto_context)): State<(Arc<Mutex<Node>>, Arc<Mutex<CryptoContext>>)>,
    Json(indicators): Json<Vec<EncryptedThreatIndicator>>,
) -> ApiResponse<serde_json::Value> {
    let crypto = crypto_context.lock().await;
    let mut node = node.lock().await;
    let mut count = 0;
    for encrypted in indicators {
        if let Ok(indicator) = ThreatIndicator::decrypt(&encrypted, &crypto) {
            node.add_or_increment_indicator(indicator);
            count += 1;
        }
    }
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "received": count })),
    ))
}

async fn get_public_indicators_handler(
    State((node, _)): State<(Arc<Mutex<Node>>, Arc<Mutex<CryptoContext>>)>,
) -> ApiResponse<Vec<serde_json::Value>> {
    let node = node.lock().await;
    let indicators = node.list_indicators_by_tlp(crate::models::TlpLevel::White);
    // Return anonymized (open) view
    let result: Vec<_> = indicators
        .iter()
        .map(|i| i.to_json(node.get_level()))
        .collect();
    Ok((StatusCode::OK, Json(result)))
}

async fn get_private_indicators_handler(
    State((node, _)): State<(Arc<Mutex<Node>>, Arc<Mutex<CryptoContext>>)>,
) -> ApiResponse<Vec<serde_json::Value>> {
    let node = node.lock().await;
    let indicators = node.list_indicators_by_tlp(crate::models::TlpLevel::Red);
    // Return anonymized (moderate) view
    let result: Vec<_> = indicators
        .iter()
        .map(|i| i.to_json(node.get_level()))
        .collect();
    Ok((StatusCode::OK, Json(result)))
}

async fn get_indicator_by_id_handler(
    State((node, _)): State<(Arc<Mutex<Node>>, Arc<Mutex<CryptoContext>>)>,
    Path(id): Path<String>,
) -> ApiResponse<serde_json::Value> {
    let node = node.lock().await;
    if let Some(indicator) = node.get_indicator_by_id(&Uuid::from_str(&id).unwrap()) {
        Ok((StatusCode::OK, Json(indicator.to_json(node.get_level()))))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: "Indicator not found".to_string(),
            }),
        ))
    }
}

// --- Log Viewer ---

async fn read_logs_handler(
    State((node, _)): State<(Arc<Mutex<Node>>, Arc<Mutex<CryptoContext>>)>,
    Path(date): Path<String>,
) -> ApiResponse<Vec<String>> {
    let node = node.lock().await;
    match node.read_logs(&date) {
        Ok(logs) => Ok((StatusCode::OK, Json(logs))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                error: format!("Failed to read logs: {}", e),
            }),
        )),
    }
}

// --- TAXII Handlers ---

async fn taxii_discovery_handler(
    State((node, _)): State<(Arc<Mutex<Node>>, Arc<Mutex<CryptoContext>>)>,
) -> Json<serde_json::Value> {
    let node = node.lock().await;
    Json(serde_json::json!({
        "title": format!("DTIM TAXII Server (node--{})", node.get_id()),
        "description": "TAXII 2.1 server for sharing threat intelligence",
        "default": "/taxii2/root/",
        "api_roots": vec!["/taxii2/root/"]
    }))
}

async fn taxii_api_root_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "title": "Default API Root",
        "description": "Main entry point for DTIM collections",
        "versions": vec!["taxii-2.1"],
        "max_content_length": 10485760
    }))
}

async fn taxii_collections_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "collections": [
            {
                "id": "indicators",
                "title": "Threat Indicators",
                "description": "Collection of shared threat indicators",
                "can_read": true,
                "can_write": true
            }
        ]
    }))
}

async fn taxii_get_objects_handler(
    State((node, _)): State<(Arc<Mutex<Node>>, Arc<Mutex<CryptoContext>>)>,
    Path(_collection_id): Path<String>,
) -> Json<serde_json::Value> {
    let node = node.lock().await;
    let stix_objects = node.list_objects_by_tlp(crate::models::TlpLevel::White);
    let bundle = StixBundle::new(stix_objects);
    Json(bundle.to_stix())
}

async fn taxii_post_objects_handler(
    State((_, _)): State<(Arc<Mutex<Node>>, Arc<Mutex<CryptoContext>>)>,
    Path(_collection_id): Path<String>,
    Json(_): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    // TODO: Parse STIX objects into ThreatIndicators
    Json(serde_json::json!({ "status": "not implemented" }))
}
