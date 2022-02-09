use reqwest::{IntoUrl, RequestBuilder};
use serde::{de::DeserializeOwned, Deserialize};

use crate::error::{AuthaError, RequestError};

#[derive(Deserialize)]
struct AuthaErrorPayload {
    error: String,
    error_message: Option<String>,
}

pub(crate) struct HttpClient {
    http: reqwest::Client,
    shared_secret: String,
}

impl HttpClient {
    pub fn new(shared_secret: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            shared_secret,
        }
    }

    pub fn post(&self, url: impl IntoUrl) -> RequestBuilder {
        self.http.post(url)
    }

    pub async fn request<T: DeserializeOwned>(
        &self,
        request: RequestBuilder,
    ) -> Result<Result<T, AuthaError>, RequestError> {
        let request = request.header("X-Autha-Shared-Secret", &self.shared_secret);
        let response = request.send().await?;

        let status_code = response.status();
        let response = if status_code.is_success() {
            let response: T = response.json().await?;
            Ok(response)
        } else {
            let response: AuthaErrorPayload = response.json().await?;
            Err(AuthaError {
                error: response.error,
                error_message: response.error_message,
                status_code,
            })
        };

        Ok(response)
    }
}
