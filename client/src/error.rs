use derive_more::{Display, Error, From};
use reqwest::StatusCode;

#[derive(From, Debug, Error, Display)]
#[display(fmt = "autha error: {} ({})", error, status_code)]
pub struct AuthaError {
    pub error: String,
    pub error_message: Option<String>,
    pub status_code: StatusCode,
}

#[derive(From, Debug, Error, Display)]
pub enum RequestError {
    Request(reqwest::Error),
    Format(serde_json::Error),
}

impl From<RequestError> for AuthaError {
    fn from(_: RequestError) -> Self {
        AuthaError {
            error: "INTERNAL_SERVER_ERROR".to_string(),
            error_message: None,
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[derive(From, Debug, Error, Display)]
pub enum StartupError {
    Jwt(RequestError),
}

#[derive(From, Debug, Error, Display)]
pub struct DecodeTokenError {
    source: jsonwebtoken::errors::Error,
}

#[derive(From, Debug, Error, Display)]
pub enum VerifyAccessTokenError {
    #[from(forward)]
    Decode(DecodeTokenError),
}

impl From<VerifyAccessTokenError> for AuthaError {
    fn from(_: VerifyAccessTokenError) -> Self {
        AuthaError {
            error: "INVALID_TOKEN".to_string(),
            error_message: Some(
                "Your login token has expired or is invalid, please login again".to_string(),
            ),
            status_code: StatusCode::UNAUTHORIZED,
        }
    }
}
