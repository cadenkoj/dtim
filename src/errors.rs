use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;
use thiserror::Error;

pub type ApiErrorResponse = (StatusCode, Json<ApiErrorBody>);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApiError {
    pub code: StatusCode,
    pub message: &'static str,
}

#[derive(Serialize)]
pub struct ApiErrorBody {
    error: &'static str,
}

impl From<ApiError> for ApiErrorResponse {
    fn from(err: ApiError) -> Self {
        (err.code, Json(ApiErrorBody { error: err.message }))
    }
}

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::error::EncodeError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Ring unspecified error")]
    Ring(ring::error::Unspecified),

    #[error("Invalid key material: {reason}")]
    InvalidKey { reason: String },

    #[error("Encryption failed: {reason}")]
    EncryptionFailed { reason: String },

    #[error("Decryption failed: all keys attempted")]
    DecryptionFailed,

    #[error("Invalid encrypted data: {reason}")]
    InvalidData { reason: String },

    #[error("Key rotation failed: {reason}")]
    KeyRotation { reason: String },

    #[error("Version {version} not found")]
    VersionNotFound { version: u32 },

    #[error("Key derivation failed: {reason}")]
    KeyDerivation { reason: String },
}

impl CryptoError {
    pub fn invalid_key(reason: impl Into<String>) -> Self {
        Self::InvalidKey {
            reason: reason.into(),
        }
    }

    pub fn encryption_failed(reason: impl Into<String>) -> Self {
        Self::EncryptionFailed {
            reason: reason.into(),
        }
    }

    pub fn invalid_data(reason: impl Into<String>) -> Self {
        Self::InvalidData {
            reason: reason.into(),
        }
    }

    pub fn key_rotation(reason: impl Into<String>) -> Self {
        Self::KeyRotation {
            reason: reason.into(),
        }
    }

    pub fn key_derivation(reason: impl Into<String>) -> Self {
        Self::KeyDerivation {
            reason: reason.into(),
        }
    }
}

macro_rules! api_errors {
    (
        $(
            $(#[$docs:meta])*
            ($code:expr, $variant:ident, $message:expr);
        )+
    ) => {
        impl ApiError {
        $(
            $(#[$docs])*
            pub const $variant: ApiError = ApiError {
                code: $code,
                message: $message,
            };
        )+
        }
    }
}

api_errors! {
    // Standard errors
    (StatusCode::INTERNAL_SERVER_ERROR, INTERNAL_SERVER_ERROR, "Internal server error");
    (StatusCode::NOT_FOUND, NOT_FOUND, "Object not found");
    (StatusCode::UNAUTHORIZED, UNAUTHORIZED, "Unauthorized");
    (StatusCode::BAD_REQUEST, BAD_REQUEST, "Bad request");

    // Custom errors
    (StatusCode::BAD_REQUEST, INVALID_STIX_OBJECT, "Invalid STIX object");
    (StatusCode::BAD_REQUEST, INVALID_INDICATOR_ID, "Invalid indicator ID");
    (StatusCode::INTERNAL_SERVER_ERROR, LOG_PARSE_ERROR, "Failed to read logs");
}
