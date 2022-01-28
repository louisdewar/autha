use actix_web::{web, HttpRequest};
use lettre::Address;
use serde::Deserialize;
use serde_json::json;

use crate::{
    db::DatabaseContext,
    error::{
        email::{AddressParseError, DomainNotAllowed},
        EndpointResult,
    },
    impl_endpoint_error,
    provider::{context::ProviderContext, flow::FlowResponse, AuthenticationProvider},
    util::generate_base64_url_safe_string,
};

use derive_more::{Display, Error};

#[derive(Display, Error, Debug)]
pub struct InvalidPassword;

impl_endpoint_error!(
    InvalidPassword,
    BAD_REQUEST,
    "INVALID_PASSWORD",
    "The password fails to meet basic requirements"
);

#[derive(Display, Error, Debug)]
pub struct PasswordAuthNotEnabled;

impl_endpoint_error!(
    PasswordAuthNotEnabled,
    BAD_REQUEST,
    "PASSWORD_AUTH_NOT_ENABLED",
    "Password auth is not enabled for this account"
);

#[derive(Display, Error, Debug)]
pub struct IncorrectCredentials;

impl_endpoint_error!(
    IncorrectCredentials,
    BAD_REQUEST,
    "INCORRECT_CREDENTIALS",
    "The username or password is incorrect"
);

#[derive(Deserialize)]
pub struct PasswordProviderConfig {
    #[serde(default)]
    allowed_email_domains: Option<Vec<String>>,
}

pub struct PasswordProvider {
    config: PasswordProviderConfig,
}

#[derive(Deserialize)]
struct RegisterParams {
    username: String,
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct LoginParams {
    // Consider only allowing logins by username and keeping email private for backup login methods.
    // We currently leak if a username or email does / does not exist, this isn't important for
    // usernames but probably is for emails.
    username_or_email: String,
    password: String,
}
const SALT_BYTES_LEN: usize = 16;
const ROUNDS: u32 = 50;
const HASH_SIZE_BYTES: usize = 32;
const MAX_PASSWORD_LEN: usize = 256;

fn hash_password(password: &str, salt: &str) -> String {
    let mut output = vec![0; HASH_SIZE_BYTES];
    bcrypt_pbkdf::bcrypt_pbkdf(
        password,
        &base64::decode(salt).expect("salt was not base64"),
        ROUNDS,
        &mut output,
    )
    .expect("bcrypt failed!");
    base64::encode(output)
}

pub fn verify(password: &str, hashed_password: &str, salt: &str) -> bool {
    let salt = base64::decode(salt).expect("Salt was not base64");
    let hashed_password = base64::decode(hashed_password).expect("hashed password was not base64");

    let mut output = vec![0; HASH_SIZE_BYTES];
    bcrypt_pbkdf::bcrypt_pbkdf(password, &salt, ROUNDS, &mut output).expect("bcrypt failed!");
    output == hashed_password
}

/// Checks if the password meets basic requirements, in future use something like zxcvbn.
fn validate_password(password: &str) -> bool {
    password.len() > 5 && password.len() < MAX_PASSWORD_LEN
}

async fn register(
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

    if let Some(allowed_domains) = &provider.config.allowed_email_domains {
        let email_domain = email.domain();
        let mut allowed = false;
        for domain in allowed_domains {
            if email_domain == domain {
                allowed = true;
                break;
            }
        }

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

    let salt = generate_base64_url_safe_string(SALT_BYTES_LEN);
    let hashed_password = hash_password(&params.password, &salt);

    db_context
        .upsert_password_auth(user.id, hashed_password, salt)
        .await?;

    FlowResponse::authenticated(user).respond_to(&req).await
}

async fn login(
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

#[async_trait::async_trait]
impl AuthenticationProvider for PasswordProvider {
    type AuthenticationConfig = PasswordProviderConfig;

    const PLUGIN_NAME: &'static str = "builtin::password";

    async fn build(
        _context: web::Data<ProviderContext>,
        config: Self::AuthenticationConfig,
    ) -> Self {
        PasswordProvider { config }
    }

    fn configure_flows(&self, config: &mut actix_web::web::ServiceConfig) {
        config.route("register", web::post().to(register));
        config.route("login", web::post().to(login));
    }
}
