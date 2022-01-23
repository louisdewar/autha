use reqwest::{Response, RequestBuilder};
use serde::{de::DeserializeOwned, Deserialize};

use crate::{Client, error::{AuthaError, RequestError}};


#[derive(Deserialize)]
struct AuthaErrorPayload {
    error: String,
    error_message: Option<String>,
}

impl Client {
    pub(crate) async fn request<T: DeserializeOwned>(&self, response: RequestBuilder) -> Result<Result<T, AuthaError>, RequestError>  {
        let response = response.bearer_auth(&self.shared_secret);
        let response = response.send().await?;

        let status_code = response.status();
        let response = if status_code.is_success() {
            let response: T = response.json().await?;
            Ok(response)
        } else {
            let response: AuthaErrorPayload = response.json().await?;
            Err(AuthaError { error: response.error, error_message: response.error_message, status_code })
        };

        Ok(response)
    }
}