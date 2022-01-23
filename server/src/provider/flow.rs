use actix_web::{
    body::{BodyStream, BoxBody},
    web, HttpResponse, Responder,
};
use futures::FutureExt;
use serde::Serialize;
use serde_json::Value;

use crate::{
    config::Config,
    db::model::User,
    email::verify::{self, EmailVerification},
    error::{email::NoEmail, EndpointResult},
};

/// A response that a successfull flow might generate.
/// Errors are generated differently
#[derive(Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
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

/// Flows that the system can create regardless of provider.
#[derive(Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum SystemFlow {
    VerifyEmail { email: String },
}


impl FlowResponse<()> {
    pub fn authenticated(user: User) -> Self {
        FlowResponse::Authenticated { user }
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

    pub async fn respond_to(self, req: &actix_web::HttpRequest) -> EndpointResult {
        let response = match self {
            FlowResponse::Authenticated { user } => {
                let config: &web::Data<Config> = req.app_data().unwrap();

                if !user.email_verified && !config.email_verify.allow_login_before_verification {
                    let verification: &web::Data<EmailVerification> = req.app_data().unwrap();
                    verify::start_verify_flow(&user, verification.clone())
                        .await
                        .map(|v| v.serialize_flow_payload())
                } else {
                    Ok(FlowResponse::Authenticated { user })
                }
            }
            flow => Ok(flow.serialize_flow_payload()),
        }?;

        Ok(HttpResponse::Ok().json(response))
    }
}

// No longer async which greatly complicated matters
// impl<T: Serialize> Responder for FlowResponse<T> {
//     type Body = BoxBody;
//
//     fn respond_to(self, req: &actix_web::HttpRequest) -> actix_web::HttpResponse<Self::Body> {
//         let response = async {
//             match self {
//                 FlowResponse::Authenticated { user } => {
//                     let config: &web::Data<Config> = req.app_data().unwrap();
//
//                     if !user.email_verified && !config.email_verify.allow_login_before_verification
//                     {
//                         let verification: &web::Data<EmailVerification> = req.app_data().unwrap();
//                         return verify::start_verify_flow(
//                             user.id,
//                             user.email.ok_or(NoEmail)?,
//                             verification.clone(),
//                         )
//                         .await;
//                     }
//
//                     Ok(FlowResponse::Authenticated { user })
//                 }
//                 flow => Ok(flow),
//             }
//         };
//
//         Box::pin(BodyStream::new(
//             async move {
//                 match response.await {
//                     Ok(response) => HttpResponse::Ok().json(response),
//                     Err(e) => e.respond_to(req),
//                 }
//             }
//             .into_stream(),
//         ))
//         .into()
//     }
// }
