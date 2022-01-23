use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{error::{RequestError, AuthaError}, Client};

#[derive(Deserialize, Debug, Clone)]
pub struct User {
    id: i32,
    username: String,
    email: Option<String>,
    email_verified: bool,
    extra: Value
}

#[derive(Deserialize, Debug, Clone)]
#[serde(tag="type")]
#[serde(rename_all = "snake_case")]
pub enum FlowResponse {
    Authenticated { user: User },
    Incomplete { payload: Value },
}


impl Client {
    pub async fn provider_flow<T: Serialize>(&self, provider_name: &str, flow_name: &str, payload: T) -> Result<Result<FlowResponse, AuthaError>, RequestError> {
        let mut url = self.autha_endpoint.clone();
        url.path_segments_mut().unwrap().extend(["provider", provider_name, "f", flow_name]);
        let response = self.http.post(url).json(&payload);

        Ok(self.request(response).await?)
    }
}