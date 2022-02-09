use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    error::{AuthaError, RequestError},
    Client,
};

#[derive(Deserialize, Debug, Clone)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub extra: Value,
    pub admin: bool,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum FlowResponse {
    Authenticated { user: User, refresh_token: String },
    Incomplete { payload: Value },
}

impl Client {
    pub async fn provider_flow<T: Serialize>(
        &self,
        provider_name: &str,
        flow_name: &str,
        payload: T,
        bearer_auth: Option<String>,
    ) -> Result<Result<FlowResponse, AuthaError>, RequestError> {
        let mut url = self.autha_endpoint.clone();
        url.path_segments_mut()
            .unwrap()
            .extend(["provider", provider_name, "f", flow_name]);
        let request = self.http.post(url).json(&payload);
        let request = if let Some(bearer) = bearer_auth {
            request.header("Authorization", bearer)
        } else {
            request
        };

        Ok(self.http.request(request).await?)
    }
}
