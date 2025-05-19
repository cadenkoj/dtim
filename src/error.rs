use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;

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

    // Custom errors
    (StatusCode::BAD_REQUEST, INVALID_STIX_OBJECT, "Invalid STIX object");
    (StatusCode::BAD_REQUEST, INVALID_INDICATOR_ID, "Invalid indicator ID");
    (StatusCode::INTERNAL_SERVER_ERROR, LOG_PARSE_ERROR, "Failed to read logs");
}
