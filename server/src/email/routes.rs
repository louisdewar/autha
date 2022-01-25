use actix_web::{
    web::{self, ServiceConfig},
    HttpRequest, HttpResponse,
};
use serde::Deserialize;

use crate::{
    db::DatabaseContext,
    error::{user::UserNotFound, EndpointResult},
    provider::flow::FlowResponse,
    redis::RedisPool,
};

use super::{verify::EmailVerification, Email, EmailClient, EmailVerificationSettings};

pub fn configure_routes(
    email_client: web::Data<EmailClient>,
    redis_pool: web::Data<RedisPool>,
    email_verification: EmailVerificationSettings,
) -> impl Fn(&mut ServiceConfig) + Clone {
    let email_verification =
        web::Data::new(email_verification.build(email_client.clone(), redis_pool));
    move |config| {
        config.app_data(email_client.clone());
        config.app_data(email_verification.clone());
        config.route("email/send", web::post().to(send_email));
        config.route("email/verify", web::post().to(verify));

        // TODO: in future
        // config.route(
        //     "email/start_verify",
        //     web::post().to(super::verify::start_verify_flow),
        // );
    }
}

#[derive(Deserialize)]
struct VerificationRequest {
    verification_code: String,
}

async fn send_email(
    email_client: web::Data<EmailClient>,
    email: web::Json<Email>,
) -> EndpointResult {
    let response = email_client.send(email.into_inner()).await?;
    dbg!(response);
    Ok(HttpResponse::Ok().into())
}

async fn verify(
    req: HttpRequest,
    email_verification: web::Data<EmailVerification>,
    request: web::Json<VerificationRequest>,
    db_context: web::Data<DatabaseContext>,
) -> EndpointResult {
    let request = request.into_inner();

    let user = email_verification
        .verify_email(&db_context, &request.verification_code)
        .await?;

    // Maybe we shouldn't respond with authenticated, maybe respond telling a
    // user their email has been verified but now they need to login
    FlowResponse::authenticated(user).respond_to(&req).await
}
