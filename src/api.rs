use axum::{
    body::{Body, Bytes},
    extract::{Json, Path, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Extension, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use base64::{prelude::BASE64_STANDARD, Engine};
use ed25519_dalek::VerifyingKey;
use http_body_util::BodyExt as _;
use rustls::ServerConfig;
use serde::Serialize;
use std::{str::FromStr as _, sync::Arc};
use tokio::sync::Mutex;

use crate::{
    crypto::MeshIdentity,
    error::{ApiError, ApiErrorResponse},
    node::{Node, NodePeer},
};
use crate::{crypto::SymmetricKeyManager, models::StixBundle};
use crate::{
    models::{EncryptedThreatIndicator, ThreatIndicator},
    uuid::Uuid,
};

#[derive(Clone)]
pub struct AppState {
    pub node: Arc<Mutex<Node>>,
    pub key_mgr: SymmetricKeyManager,
}

type ApiResponse<T> = Result<(StatusCode, Json<T>), ApiErrorResponse>;

async fn auth(req: Request, next: Next) -> Result<Response, ApiErrorResponse> {
    let (parts, body) = req.into_parts();
    let headers = &parts.headers;

    let pubkey = headers
        .get("X-Mesh-Public-Key")
        .and_then(|header| header.to_str().ok());
    let sig = headers
        .get("X-Mesh-Signature")
        .and_then(|header| header.to_str().ok());
    let bytes = body
        .collect()
        .await
        .map_err(|_| ApiError::INTERNAL_SERVER_ERROR)?
        .to_bytes();

    let auth_data = if let (Some(pubkey), Some(sig)) = (pubkey, sig) {
        (pubkey.to_string(), sig.to_string(), &bytes)
    } else {
        return Err(ApiError::UNAUTHORIZED.into());
    };

    if let Some(node_id) = authorize_client_node(auth_data).await {
        let mut req = Request::from_parts(parts, Body::from(bytes));
        req.extensions_mut().insert(node_id);
        Ok(next.run(req).await)
    } else {
        Err(ApiError::UNAUTHORIZED.into())
    }
}

async fn authorize_client_node(
    (pubkey, sig, body): (String, String, &Bytes),
) -> Option<MeshIdentity> {
    let pub_bytes: [u8; 32] = BASE64_STANDARD
        .decode(pubkey)
        .ok()
        .and_then(|bytes| bytes.as_slice().try_into().ok())?;

    let verifying_key = VerifyingKey::from_bytes(&pub_bytes).ok()?;
    let valid = MeshIdentity::verify(verifying_key, body, &sig);
    let node_id = MeshIdentity::derive_hex_id(&pub_bytes);
    // TODO: Check if the node is registered (persist in db)
    if valid {
        Some(MeshIdentity::Remote {
            id: node_id,
            verifying_key: Box::new(verifying_key),
        })
    } else {
        None
    }
}

pub async fn start_server(
    node: Arc<Mutex<Node>>,
    key_mgr: SymmetricKeyManager,
    config: Arc<ServerConfig>,
    address: String,
    port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Router::new()
        // Peer registry endpoints
        .route("/api/v1/echo", post(echo_handler))
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
        .with_state(Arc::new(AppState { node, key_mgr }))
        .layer(middleware::from_fn(auth));

    let addr = format!("{}:{}", address, port).parse()?;
    let tls_config = RustlsConfig::from_config(config);
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await
        .map_err(|e| std::io::Error::other(format!("Failed to start server: {}", e)))?;
    Ok(())
}

#[derive(Serialize)]
struct EchoResponse {
    status: String,
    node_id: String,
}

async fn echo_handler(
    Extension(mesh_identity): Extension<MeshIdentity>,
) -> ApiResponse<EchoResponse> {
    Ok((
        StatusCode::OK,
        Json(EchoResponse {
            status: "ok".to_string(),
            node_id: mesh_identity.id().clone(),
        }),
    ))
}

// --- Peer Registry Handlers ---

#[derive(Serialize)]
struct NodePeersResponse {
    status: String,
    peers: Vec<NodePeer>,
}

async fn register_node_handler(
    Extension(_): Extension<MeshIdentity>,
    State(state): State<Arc<AppState>>,
    Json(peer): Json<NodePeer>,
) -> ApiResponse<NodePeersResponse> {
    let mut node = state.node.lock().await;
    node.add_peer(&peer);
    Ok((
        StatusCode::OK,
        Json(NodePeersResponse {
            status: "ok".to_string(),
            peers: node.get_peers().values().cloned().collect(),
        }),
    ))
}

async fn get_peers_handler(State(state): State<Arc<AppState>>) -> ApiResponse<NodePeersResponse> {
    let node = state.node.lock().await;
    Ok((
        StatusCode::OK,
        Json(NodePeersResponse {
            status: "ok".to_string(),
            peers: node.get_peers().values().cloned().collect(),
        }),
    ))
}

// --- Indicator Handlers ---

#[derive(Serialize)]
struct GossipIndicatorsResponse {
    status: String,
    received: usize,
}

async fn gossip_indicators_handler(
    State(state): State<Arc<AppState>>,
    Json(indicators): Json<Vec<EncryptedThreatIndicator>>,
) -> ApiResponse<GossipIndicatorsResponse> {
    let mut node = state.node.lock().await;
    let mut count = 0;
    for encrypted in indicators {
        if let Ok(indicator) = ThreatIndicator::decrypt(&encrypted, &state.key_mgr) {
            node.add_or_increment_indicator(indicator);
            count += 1;
        }
    }
    Ok((
        StatusCode::OK,
        Json(GossipIndicatorsResponse {
            status: "ok".to_string(),
            received: count,
        }),
    ))
}

#[derive(Serialize)]
struct GetIndicatorsResponse {
    status: String,
    indicators: Vec<ThreatIndicator>,
}

async fn get_public_indicators_handler(
    State(state): State<Arc<AppState>>,
) -> ApiResponse<GetIndicatorsResponse> {
    let node = state.node.lock().await;
    let indicators = node.list_indicators_by_tlp(crate::models::TlpLevel::White);
    // Return anonymized (open) view
    Ok((
        StatusCode::OK,
        Json(GetIndicatorsResponse {
            status: "ok".to_string(),
            indicators: indicators.to_vec(),
        }),
    ))
}

async fn get_private_indicators_handler(
    State(state): State<Arc<AppState>>,
) -> ApiResponse<GetIndicatorsResponse> {
    let node = state.node.lock().await;
    let indicators = node.list_indicators_by_tlp(crate::models::TlpLevel::Red);
    // TODO: Ensure the node is an authenticated recipient for private indicators
    // Return anonymized (moderate) view
    Ok((
        StatusCode::OK,
        Json(GetIndicatorsResponse {
            status: "ok".to_string(),
            indicators: indicators.to_vec(),
        }),
    ))
}

async fn get_indicator_by_id_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResponse<serde_json::Value> {
    let node = state.node.lock().await;
    let id = Uuid::from_str(&id).map_err(|_| ApiError::INVALID_INDICATOR_ID)?;
    let indicator = node.get_indicator_by_id(&id).ok_or(ApiError::NOT_FOUND)?;
    Ok((StatusCode::OK, Json(indicator.to_json(node.get_level()))))
}

// --- Log Viewer ---

async fn read_logs_handler(
    State(state): State<Arc<AppState>>,
    Path(date): Path<String>,
) -> ApiResponse<Vec<String>> {
    let node = state.node.lock().await;
    let logs = node
        .read_logs(&date)
        .map_err(|_| ApiError::LOG_PARSE_ERROR)?;
    Ok((StatusCode::OK, Json(logs)))
}

// --- TAXII Handlers ---

async fn taxii_discovery_handler(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let node = state.node.lock().await;
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
    State(state): State<Arc<AppState>>,
    Path(_collection_id): Path<String>,
) -> ApiResponse<serde_json::Value> {
    let node = state.node.lock().await;
    let stix_objects = node.list_objects_by_tlp(crate::models::TlpLevel::White);
    let bundle = StixBundle::new(stix_objects);
    Ok((StatusCode::OK, Json(bundle.to_stix())))
}

async fn taxii_post_objects_handler(
    State(state): State<Arc<AppState>>,
    Path(_collection_id): Path<String>,
    Json(stix): Json<serde_json::Value>,
) -> ApiResponse<serde_json::Value> {
    let indicator = ThreatIndicator::from_stix(stix).map_err(|_| ApiError::INVALID_STIX_OBJECT)?;
    let mut node = state.node.lock().await;
    node.add_indicator(indicator);
    Ok((StatusCode::OK, Json(serde_json::json!({ "status": "ok" }))))
}
