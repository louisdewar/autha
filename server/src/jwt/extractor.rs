use std::pin::Pin;

use actix_web::{web, FromRequest};
use futures::Future;

use crate::error::{DynamicEndpointError, EndpointResult};
use crate::jwt::error::{InvalidAuthorizationHeader, MissingAuthorizationHeader};
use crate::provider::ProviderContext;

use super::AccessToken;

impl FromRequest for AccessToken {
    type Error = DynamicEndpointError;

    type Future = Pin<Box<dyn Future<Output = EndpointResult<AccessToken>>>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let auth_header = req.headers().get("AUTHORIZATION").cloned();
        let provider_context = req
            .app_data::<web::Data<ProviderContext>>()
            .unwrap()
            .clone();

        Box::pin(async move {
            let auth_header = auth_header
                .ok_or(MissingAuthorizationHeader)?
                .to_str()
                .map(|s| s.to_string())
                .map_err(|_| InvalidAuthorizationHeader)?;

            if auth_header.len() < 8 || &auth_header[0..7] != "Bearer " {
                return Err(InvalidAuthorizationHeader.into());
            }

            let token = &auth_header[7..];

            let access_token = provider_context.decode_access_token(token)?;

            Ok(access_token)
        })
    }
}
