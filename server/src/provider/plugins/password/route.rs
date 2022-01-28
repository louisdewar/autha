use actix_web::{web, HttpRequest};
use lettre::Address;
use serde_json::json;

use crate::{
    db::DatabaseContext,
    error::{
        email::{AddressParseError, DomainNotAllowed},
        EndpointResult,
    },
    provider::{flow::FlowResponse, ProviderContext},
};

use super::{
    error::{IncorrectCredentials, InvalidPassword, PasswordAuthNotEnabled},
    request::{LoginParams, RegisterParams},
    util::{generate_salt, hash_password, validate_password, verify},
    PasswordProvider,
};

pub async fn register(
    req: HttpRequest,
    db_context: web::Data<DatabaseContext>,
    provider_context: web::Data<ProviderContext>,
    provider: web::Data<PasswordProvider>,
    params: web::Json<RegisterParams>,
) -> EndpointResult {
    let params = params.into_inner();

    let email: Address = params.email.parse().map_err(AddressParseError::from)?;

    if !validate_password(&params.password) {
        return Err(InvalidPassword.into());
    }

    let email_domain = email.domain();
    if let Some(allowed_domains) = &provider.config.allowed_email_domains {
        let allowed = allowed_domains
            .iter()
            .any(|allowed_domain| email_domain.ends_with(allowed_domain.as_str()));

        if !allowed {
            return Err(DomainNotAllowed.into());
        }
    }

    let user = provider_context
        .register_user(
            params.username,
            email.to_string(),
            json!({ "org": email.domain() }),
        )
        .await?;

    let salt = generate_salt();
    let hashed_password = hash_password(&params.password, &salt);

    db_context
        .upsert_password_auth(user.id, hashed_password, salt)
        .await?;

    FlowResponse::authenticated(user).respond_to(&req).await
}

pub async fn login(
    req: HttpRequest,
    db_context: web::Data<DatabaseContext>,
    provider_context: web::Data<ProviderContext>,
    params: web::Json<LoginParams>,
) -> EndpointResult {
    let params = params.into_inner();

    // NOTE/TODO:
    // With a timing attack whether an username or email exists or not could be detected.
    // This doesn't really matter for usernames but it probably does for emails.
    // Either remove the ability for emails to be used or add a random delay.

    // Then again you can figure out if an email is used in the register form
    let user = provider_context
        .get_user_by_username_or_email(params.username_or_email)
        .await?
        .ok_or(IncorrectCredentials)?;

    let password_auth = db_context
        .get_password_auth(user.id)
        .await?
        .ok_or(PasswordAuthNotEnabled)?;

    if !verify(
        &params.password,
        &password_auth.hashed_password,
        &password_auth.salt,
    ) {
        return Err(IncorrectCredentials.into());
    }

    FlowResponse::authenticated(user).respond_to(&req).await
}

