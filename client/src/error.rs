use derive_more::{From, Error, Display};
use reqwest::StatusCode;
use serde::Deserialize;

// pub trait AuthaError: std::error::Error + Send + Sync + 'static {
//     fn status(&self) -> StatusCode;
//     fn error_code(&self) -> String;
//     fn error_message(&self) -> Option<String>;
// }

#[derive(From, Debug, Error, Display)]
pub enum RequestError {
    Request(reqwest::Error),
    Format(serde_json::Error),
}

#[derive(From, Debug, Error, Display)]
#[display(fmt="autha error: {} ({})", error, status_code)]
pub struct AuthaError {
    pub error: String,
    pub error_message: Option<String>,
    pub status_code: StatusCode
}
