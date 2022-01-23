use serde::Serialize;
use reqwest::RequestBuilder;

use crate::{Client, flow::FlowResponse, error::{RequestError, AuthaError}};

impl Client {
    pub async fn verify_email<T: Serialize>(&self, payload: T) -> Result<Result<FlowResponse, AuthaError>, RequestError> {
        let mut url = self.autha_endpoint.clone();
        url.path_segments_mut().unwrap().extend(["email", "verify"]);
        let response: RequestBuilder= self.http.post(url).json(&payload);

        Ok(self.request(response).await?)
    }
}