use std::time::Duration;

use crate::{
    db::{model::User, DatabaseContext},
    error::{
        email::{InvalidVerificationCode, InvalidVerificationTemplate, NoEmail},
        EndpointError,
    },
    provider::flow::{FlowResponse, SystemFlow},
    redis::{self, RedisPool},
};

use actix_web::web;
use lettre::Address;
use rand::Rng;
use serde::Deserialize;
use tera::{Context, Tera};
use tracing::info;
use url::Url;

use super::EmailClient;

/// Number of bytes of randomness for the verification code.
/// It is then encoded base64.
const VERIFICATION_CODE_LEN: usize = 16;
// Lasts 2 days
const VERIFICATION_EXPIRATION: Duration = Duration::from_secs(60 * 60 * 24 * 2);

pub struct EmailVerification {
    email_client: web::Data<EmailClient>,
    tera: Tera,
    verify_url: Url,
    email_subject: String,
    redis_pool: web::Data<RedisPool>,
}

#[derive(Deserialize, Clone)]
pub struct EmailVerificationSettings {
    #[serde(default = "crate::util::default_true")]
    pub enabled: bool,
    pub verify_url: String,
    #[serde(default)]
    pub allow_login_before_verification: bool,
    pub email_subject: String,
    pub email_template: String,
}

impl Default for EmailVerificationSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            verify_url: Default::default(),
            allow_login_before_verification: true,
            email_subject: Default::default(),
            email_template: Default::default(),
        }
    }
}

impl EmailVerificationSettings {
    pub fn build(
        self,
        email_client: web::Data<EmailClient>,
        redis_pool: web::Data<RedisPool>,
    ) -> EmailVerification {
        let mut tera = Tera::default();

        tera.add_raw_template("verification_email", &self.email_template)
            .expect("invalid email verification template");

        EmailVerification {
            email_client,
            tera,
            email_subject: self.email_subject,
            redis_pool,
            verify_url: self.verify_url.parse().expect("invalid verify_url"),
        }
    }
}

impl EmailVerification {
    /// Generates a new random string to use as a verification code (url safe) and stores it in the
    /// database.
    // NOTE:
    // It's probably important that we store both the user id and the email we're verifying to
    // stop a potential attack where the user changes their email during a verification (if we
    // ever make that possible) and then we accidentally verify the wrong email.
    async fn generate_and_store_code(
        &self,
        user_id: i32,
        email: &str,
    ) -> Result<String, Box<dyn EndpointError>> {
        let mut rng = rand::thread_rng();

        // The exact value doesn't matter, we just use this to generate a string.
        // By generating a u128 first and then encoding it we guarantee 128 bits of randomness.
        let verification_numbers: [u8; VERIFICATION_CODE_LEN] = rng.gen();
        let verification_code =
            base64::encode_config(&verification_numbers, base64::URL_SAFE_NO_PAD);

        let mut conn = self.redis_pool.get().await?;

        redis::action::email_verification::set_email_verification(
            &mut conn,
            user_id,
            email.to_string(),
            &verification_code,
            VERIFICATION_EXPIRATION,
        )
        .await?;

        Ok(verification_code)
    }

    /// Handles a new email verification request, including generating the code, storing it and
    /// sending the email
    async fn new_verification(
        &self,
        user: &User,
        email: &str,
    ) -> Result<(), Box<dyn EndpointError>> {
        let code = self.generate_and_store_code(user.id, email).await?;

        let mut url = self.verify_url.clone();
        url.query_pairs_mut()
            .append_pair("verification_code", &code);
        let url: String = url.into();
        let mut context = Context::new();
        context.insert("verification_url", &url);
        context.insert("name", &user.username);
        let content = self
            .tera
            .render("verification_email", &context)
            .map_err(InvalidVerificationTemplate::from)?;

        self.email_client
            .send(super::Email {
                to: email.to_owned(),
                subject: self.email_subject.clone(),
                content,
            })
            .await?;
        info!(user_id=?user.id, username=?user.username, email=?email, "sending verification email to user");

        Ok(())
    }

    pub async fn verify_email(
        &self,
        db_context: &DatabaseContext,
        verification_code: &str,
    ) -> Result<User, Box<dyn EndpointError>> {
        let mut conn = self.redis_pool.get().await?;

        let meta = redis::action::email_verification::take_email_verification(
            &mut conn,
            verification_code,
        )
        .await?
        .ok_or(InvalidVerificationCode)?;

        let user = db_context
            .mark_email_as_verified(meta.user_id, meta.email)
            .await?;
        info!(user_id=?user.id, username=?user.username, email=?user.email, "user verified email");

        Ok(user)
    }
}

// TODO: move into method of EmailVerification
/// Generates a unique code and sends a verifiation for the user returning the flow response that
/// should be sent (eventually) to the user.
pub async fn start_verify_flow(
    user: &User,
    verification: web::Data<EmailVerification>,
) -> Result<FlowResponse<SystemFlow>, Box<dyn EndpointError>> {
    let email = user.email.clone().ok_or(NoEmail)?;
    verification.new_verification(user, &email).await?;

    let email: Address = email.parse().expect("email in database was not valid");

    Ok(FlowResponse::incomplete(SystemFlow::VerifyEmail {
        start_letter: email.user().chars().next().unwrap().into(),
        domain: email.domain().to_string(),
    }))
}
