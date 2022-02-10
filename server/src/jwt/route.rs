use actix_web::{
    web::{self, ServiceConfig},
    HttpResponse,
};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    config::Config,
    db::DatabaseContext,
    error::{user::UserNotFound, EndpointResult},
    provider::ProviderContext,
};

use super::JwtSettings;

pub fn configure_routes(
    jwt_settings: web::Data<JwtSettings>,
) -> impl Fn(&mut ServiceConfig) + Clone {
    let jwt_settings = jwt_settings;
    move |config| {
        config.app_data(jwt_settings.clone());

        config.route("jwt/permission/make_admin", web::post().to(make_admin));
        config.route("jwt/authorize", web::post().to(authorize));
        config.route("jwt/issue_refresh", web::post().to(issue_refresh));
        config.route("jwt/info", web::post().to(discover_jwt_info));
    }
}

#[derive(Serialize)]
struct JwtInfoResponse {
    jwt_decoding_secret: String,
    aud: String,
}

#[derive(Deserialize)]
struct AuthorizeRequest {
    refresh_token: String,
}

#[derive(Serialize)]
struct AuthorizeResponse {
    access_token: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum MakeAdminRequest {
    ById { user_id: i32 },
    ByUsername { username: String },
}

#[derive(Deserialize)]
struct IssueRefreshRequest {
    user_id: i32,
}

#[derive(Serialize)]
struct IssueRefreshResponse {
    refresh_token: String,
}

async fn discover_jwt_info(
    jwt_settings: web::Data<JwtSettings>,
    config: web::Data<Config>,
) -> HttpResponse {
    HttpResponse::Ok().json(JwtInfoResponse {
        jwt_decoding_secret: config.jwt.secret.clone(),
        aud: jwt_settings.token_aud.clone(),
    })
}

async fn authorize(
    provider_context: web::Data<ProviderContext>,
    request: web::Json<AuthorizeRequest>,
) -> EndpointResult {
    let refresh_token = provider_context
        .decode_refresh_token(&request.refresh_token)
        .await?;
    let access_token = provider_context
        .generate_access_token(&refresh_token)
        .await?;

    Ok(HttpResponse::Ok().json(AuthorizeResponse { access_token }))
}

async fn issue_refresh(
    provider_context: web::Data<ProviderContext>,
    request: web::Json<IssueRefreshRequest>,
) -> EndpointResult {
    let refresh_token = provider_context
        .generate_refresh_token(request.user_id)
        .await?;
    Ok(HttpResponse::Ok().json(IssueRefreshResponse { refresh_token }))
}

async fn make_admin(
    database_context: web::Data<DatabaseContext>,
    request: web::Json<MakeAdminRequest>,
) -> EndpointResult {
    let user_id = match request.into_inner() {
        MakeAdminRequest::ById { user_id } => user_id,
        MakeAdminRequest::ByUsername { username } => {
            let user = database_context
                .get_user_by_username_or_email(username)
                .await?
                .ok_or(UserNotFound)?;
            user.id
        }
    };

    let user = database_context
        .set_user_admin_status(user_id, true)
        .await?;
    info!(username=%user.username, user_id=%user.id, "made user admin");
    Ok(HttpResponse::Ok().json(serde_json::json!({})))
}
