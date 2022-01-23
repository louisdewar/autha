use lettre::{
    message::Mailbox,
    transport::smtp::{self, authentication::Credentials},
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use serde::Deserialize;

mod routes;
pub mod verify;

pub use routes::configure_routes;
pub use verify::EmailVerificationSettings;

use crate::error::{email::AddressParseError, EndpointError};

/// Client for sending email
pub struct EmailClient {
    from_address: Mailbox,
    smtp_transport: AsyncSmtpTransport<Tokio1Executor>,
}

#[derive(Deserialize, Clone)]
pub struct EmailClientConfig {
    username: String,
    password: String,
    server: String,
    from_address: String,
}

#[derive(Deserialize)]
pub struct Email {
    pub to: String,
    pub subject: String,
    pub content: String,
}

impl EmailClient {
    pub fn build(config: EmailClientConfig) -> Self {
        let smtp_transport = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.server)
            .unwrap()
            .credentials(Credentials::new(config.username, config.password))
            .build();

        EmailClient {
            from_address: config.from_address.parse().unwrap(),
            smtp_transport,
        }
    }

    pub async fn send(
        &self,
        email: Email,
    ) -> Result<smtp::response::Response, Box<dyn EndpointError>> {
        let email = Message::builder()
            .to(email.to.parse().map_err(AddressParseError::from)?)
            .from(self.from_address.clone())
            .subject(email.subject)
            .body(email.content)
            .unwrap();

        let res = self.smtp_transport.send(email).await?;
        Ok(res)
    }
}

impl EmailClientConfig {
    pub fn build(self) -> EmailClient {
        EmailClient::build(self)
    }
}
