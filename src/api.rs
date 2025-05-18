use crate::models::EncryptedThreatIndicator;
use crate::node::Node;
use crate::{crypto::CryptoContext, models::ThreatIndicator};
use axum::extract::Path;
use axum::{
    extract::{Json, State},
    http::StatusCode,
    routing::{get, post},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use rustls::ServerConfig;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(serde::Serialize)]
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
        .route("/share", post(share_handler))
        .route("/indicators", get(get_all_handler))
        .route("/logs/{date}", get(read_logs_handler))
        .with_state((node, crypto_context));

    let addr = format!("0.0.0.0:{}", port).parse()?;

    let tls_config = RustlsConfig::from_config(config);
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}

async fn share_handler(
    State((node, crypto_context)): State<(Arc<Mutex<Node>>, Arc<Mutex<CryptoContext>>)>,
    Json(encrypted): Json<EncryptedThreatIndicator>,
) -> ApiResponse<uuid::Uuid> {
    let crypto = crypto_context.lock().await;
    match ThreatIndicator::decrypt(&encrypted, &crypto) {
        Ok(indicator) => {
            let mut node = node.lock().await;
            let id = node.add_indicator(indicator);
            Ok((StatusCode::OK, Json(id)))
        }
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(ApiError { error: e }))),
    }
}

async fn get_all_handler(
    State((node, crypto_context)): State<(Arc<Mutex<Node>>, Arc<Mutex<CryptoContext>>)>,
) -> ApiResponse<Vec<EncryptedThreatIndicator>> {
    let node = node.lock().await;
    let mut crypto = crypto_context.lock().await;
    crypto.rotate_key();

    let indicators = node.list_indicators();
    let encrypted_indicators: Vec<EncryptedThreatIndicator> = indicators
        .iter()
        .map(|indicator| indicator.encrypt(&crypto))
        .collect();

    Ok((StatusCode::OK, Json(encrypted_indicators)))
}

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
