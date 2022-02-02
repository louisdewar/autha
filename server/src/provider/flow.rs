use actix_web::{web, HttpResponse};
use serde::Serialize;
use serde_json::Value;
use tracing::info;

use crate::{
    config::Config,
    db::model::User,
    email::verify::{self, EmailVerification},
    error::{DynamicEndpointError, EndpointResult},
};

use super::ProviderContext;

/// A response that a successfull flow might generate.
/// Errors are generated differently
pub enum FlowResponse<T: Serialize> {
    /// If the provider was able to authenticate the user.
    /// The user may or may not be a new user, it is up to the client server to check.
    ///
    /// NOTE: this may not be the final response returned.
    /// For example, if unverified email logins are disabled **and** the user has not verified
    /// their email then this will be turned into an email verification flow.
    Authenticated { user: User },
    /// More steps are needed to complete the authentication and the payload contains provider
    /// specific information that the client can use to make progress.
    ///
    /// The payload should be tagged using `#[serde(tag = "type")]` or manually tagged so that each variant has `type:
    /// "VARIANT_TYPE_STRING"`
    /// TODO: think of better name that doesn't conflict with the overall flow response that
    /// contains authentication
    Incomplete { payload: T },
}

#[derive(Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
enum FlowResponseSerializable {
    /// If the provider was able to authenticate the user.
    /// The user may or may not be a new user, it is up to the client server to check.
    ///
    /// NOTE: this may not be the final response returned.
    /// For example, if unverified email logins are disabled **and** the user has not verified
    /// their email then this will be turned into an email verification flow.
    Authenticated { user: User, refresh_token: String },
    /// More steps are needed to complete the authentication and the payload contains provider
    /// specific information that the client can use to make progress.
    ///
    /// The payload should be tagged using `#[serde(tag = "type")]` or manually tagged so that each variant has `type:
    /// "VARIANT_TYPE_STRING"`
    /// TODO: think of better name that doesn't conflict with the overall flow response that
    /// contains authentication
    Incomplete { payload: serde_json::Value },
}

/// Flows that the system can create regardless of provider.
#[derive(Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum SystemFlow {
    VerifyEmail {
        start_letter: String,
        domain: String,
    },
}

impl FlowResponse<()> {
    pub fn authenticated(user: User) -> Self {
        FlowResponse::Authenticated { user }
    }
}

impl FlowResponse<serde_json::Value> {
    async fn finish(
        self,
        provider_context: &ProviderContext,
    ) -> Result<FlowResponseSerializable, DynamicEndpointError> {
        Ok(match self {
            FlowResponse::Incomplete { payload } => {
                FlowResponseSerializable::Incomplete { payload }
            }
            FlowResponse::Authenticated { user } => {
                // generate refresh token
                let refresh_token = provider_context.generate_refresh_token(user.id).await?;
                FlowResponseSerializable::Authenticated {
                    user,
                    refresh_token,
                }
            }
        })
    }
}

impl<T: Serialize> FlowResponse<T> {
    pub fn incomplete(payload: T) -> Self {
        FlowResponse::Incomplete { payload }
    }

    fn serialize_flow_payload(self) -> FlowResponse<Value> {
        match self {
            FlowResponse::Incomplete { payload } => FlowResponse::Incomplete {
                payload: serde_json::to_value(payload).unwrap(),
            },
            FlowResponse::Authenticated { user } => FlowResponse::Authenticated { user },
        }
    }

    pub async fn respond_to(
        self,
        req: &actix_web::HttpRequest,
        provider_context: &ProviderContext,
    ) -> EndpointResult {
        let response = match self {
            FlowResponse::Authenticated { user } => {
                let config: &web::Data<Config> = req.app_data().unwrap();

                if !user.email_verified && !config.email_verify.allow_login_before_verification {
                    let verification: &web::Data<EmailVerification> = req.app_data().unwrap();
                    info!(user_id=?user.id, username=?user.username, "blocking user authentication because email is not verified");
                    verify::start_verify_flow(&user, verification.clone())
                        .await
                        .map(|v| v.serialize_flow_payload())
                } else {
                    info!(user_id=?user.id, username=?user.username, "successfully authenticated user");
                    Ok(FlowResponse::Authenticated { user })
                }
            }
            flow => Ok(flow.serialize_flow_payload()),
        }?;

        let response = response.finish(provider_context).await?;

        Ok(HttpResponse::Ok().json(response))
    }
}
