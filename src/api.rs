use crate::models::ThreatIndicator;
use crate::node::Node;
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
    config: Arc<ServerConfig>,
    port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Router::new()
        .route("/share", post(share_handler))
        .route("/indicators", get(get_all_handler))
        .with_state(node);

    let addr = format!("0.0.0.0:{}", port).parse()?;

    let tls_config = RustlsConfig::from_config(config);
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}

async fn share_handler(
    State(node): State<Arc<Mutex<Node>>>,
    Json(indicator): Json<ThreatIndicator>,
) -> ApiResponse<uuid::Uuid> {
    let mut node = node.lock().await;
    let id = node.add_indicator(indicator);
    Ok((StatusCode::OK, Json(id)))
}

async fn get_all_handler(
    State(node): State<Arc<Mutex<Node>>>,
) -> ApiResponse<Vec<ThreatIndicator>> {
    let node = node.lock().await;
    let indicators = node.list_indicators();

    Ok((StatusCode::OK, Json(indicators)))
}
