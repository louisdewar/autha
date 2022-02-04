use std::time::Duration;

use actix_web::{web, HttpRequest};
use lettre::Address;
use serde_json::json;
use tera::Context;
use tracing::{debug, info};

use crate::{
    db::DatabaseContext,
    email::{Email, EmailClient},
    error::{
        email::{AddressParseError, DomainNotAllowed},
        user::UserNotFound,
        EndpointResult,
    },
    jwt::AccessToken,
    provider::{flow::FlowResponse, ProviderContext},
    redis::{self, RedisPool},
};

use super::{
    error::{
        IncorrectCredentials, InvalidPassword, OldPasswordIncorrect, PasswordAuthNotEnabled,
        PasswordResetExpired,
    },
    request::{
        ChangePasswordParams, LoginParams, RegisterParams, RequestResetPasswordParams,
        ResetPasswordParams,
    },
    response::PasswordProviderIncompleteFlow,
    util::{generate_salt, hash_password, validate_password, verify},
    PasswordProvider,
};

/// Number of bytes of randomness for the verification code.
/// It is then encoded base64.
const VERIFICATION_CODE_LEN: usize = 16;
// Lasts 2 days
const VERIFICATION_EXPIRATION: Duration = Duration::from_secs(60 * 60 * 24 * 2);

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

    FlowResponse::authenticated(user)
        .respond_to(&req, &provider_context)
        .await
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

    FlowResponse::authenticated(user)
        .respond_to(&req, &provider_context)
        .await
}

pub async fn request_reset_password(
    req: HttpRequest,
    redis_pool: web::Data<RedisPool>,
    provider_context: web::Data<ProviderContext>,
    provider: web::Data<PasswordProvider>,
    email_client: web::Data<EmailClient>,
    params: web::Json<RequestResetPasswordParams>,
    db_context: web::Data<DatabaseContext>,
) -> EndpointResult {
    let email = params.into_inner().email;
    // TODO: use get_user_by_email otherwise people will be able to enter a username to send spam verification emails to
    let user = provider_context
        .get_user_by_username_or_email(email.clone())
        .await?
        .ok_or(UserNotFound)?;

    let password_auth = db_context
        .get_password_auth(user.id)
        .await?
        .ok_or(PasswordAuthNotEnabled)?;

    let verification_code = crate::util::generate_base64_url_safe_string(VERIFICATION_CODE_LEN);

    let mut conn = redis_pool.get().await?;

    redis::action::reset_password::set_password_reset(
        &mut conn,
        user.id,
        password_auth.hashed_password,
        &verification_code,
        VERIFICATION_EXPIRATION,
    )
    .await?;

    let mut url = provider.reset_url.clone();
    url.query_pairs_mut()
        .append_pair("verification_code", &verification_code);
    let url: String = url.into();
    let mut context = Context::new();
    context.insert("verification_url", &url);
    context.insert("name", &user.username);
    let content = provider
        .tera
        .render("reset_password_email", &context)
        .expect("failed to render reset password template");

    email_client
        .send(Email {
            to: email.clone(),
            subject: "Password reset".into(),
            content,
        })
        .await?;
    info!(user_id=?user.id, username=?user.username, email=?email, "sending password reset email to user");

    FlowResponse::incomplete(PasswordProviderIncompleteFlow::ResetPasswordEmailSent)
        .respond_to(&req, &provider_context)
        .await
}

pub async fn reset_password(
    req: HttpRequest,
    redis_pool: web::Data<RedisPool>,
    provider_context: web::Data<ProviderContext>,
    db_context: web::Data<DatabaseContext>,
    params: web::Json<ResetPasswordParams>,
) -> EndpointResult {
    let mut conn = redis_pool.get().await?;

    let meta =
        redis::action::reset_password::take_password_reset(&mut conn, &params.verification_code)
            .await?
            .ok_or(PasswordResetExpired)?;

    let user = provider_context
        .get_user_by_id(meta.user_id)
        .await?
        .ok_or(UserNotFound)?;

    let password_auth = db_context
        .get_password_auth(user.id)
        .await?
        .ok_or(PasswordAuthNotEnabled)?;

    if password_auth.hashed_password != meta.old_password_hash {
        debug!(username=%user.username, "old password hash does not match, password has been reset since code sent");
        return Err(PasswordResetExpired.into());
    }

    let salt = generate_salt();
    let hashed_password = hash_password(&params.new_password, &salt);

    db_context
        .upsert_password_auth(user.id, hashed_password, salt)
        .await?;

    debug!(username=%user.username, "reset user password");

    FlowResponse::incomplete(PasswordProviderIncompleteFlow::PasswordReset)
        .respond_to(&req, &provider_context)
        .await
}

pub async fn change_password(
    req: HttpRequest,
    db_context: web::Data<DatabaseContext>,
    provider_context: web::Data<ProviderContext>,
    params: web::Json<ChangePasswordParams>,
    access_token: AccessToken,
) -> EndpointResult {
    let params = params.into_inner();

    let user = provider_context
        .get_user_by_id(access_token.id())
        .await?
        .ok_or(UserNotFound)?;

    let password_auth = db_context
        .get_password_auth(user.id)
        .await?
        .ok_or(PasswordAuthNotEnabled)?;

    if !verify(
        &params.old_password,
        &password_auth.hashed_password,
        &password_auth.salt,
    ) {
        return Err(OldPasswordIncorrect.into());
    }

    let salt = generate_salt();
    let hashed_password = hash_password(&params.new_password, &salt);

    db_context
        .upsert_password_auth(user.id, hashed_password, salt)
        .await?;

    FlowResponse::incomplete(PasswordProviderIncompleteFlow::PasswordChanged)
        .respond_to(&req, &provider_context)
        .await
}
