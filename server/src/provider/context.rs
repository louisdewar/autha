use actix_web::web;
use lettre::Address;
use serde_json::Value;

use crate::db::model::User;
use crate::db::{DatabaseContext, PgPool};
use crate::error::email::AddressParseError;
use crate::error::DynamicEndpointError;
use crate::HTTPClient;

pub struct ProviderContext {
    db_context: DatabaseContext,
    http_client: HTTPClient,
}

impl ProviderContext {
    pub fn new(db_pool: web::Data<PgPool>) -> Self {
        ProviderContext {
            db_context: DatabaseContext::new(db_pool),
            http_client: HTTPClient::new(),
        }
    }

    pub async fn get_user_by_username_or_email(
        &self,
        username_or_email: String,
    ) -> Result<Option<User>, DynamicEndpointError> {
        self.db_context
            .get_user_by_username_or_email(username_or_email)
            .await
    }

    pub fn http_client(&self) -> &HTTPClient {
        &self.http_client
    }

    /// Validates that the username and email are valid, by checking the username for certain
    /// naming constraints and ensuring that the email can be parsed correctly (does not check
    /// anything about the email beyond that).
    ///
    /// Then this inserts the user into the database.
    pub async fn register_user(
        &self,
        username: String,
        email: String,
        extra: Value,
    ) -> Result<User, DynamicEndpointError> {
        let email: Address = email.parse().map_err(AddressParseError::from)?;
        crate::util::validate_username(&username)?;

        self.db_context
            .insert_user(username, email.to_string(), extra)
            .await
    }

    pub async fn mark_email_as_verified(
        &self,
        user_id: i32,
        email: String,
    ) -> Result<User, DynamicEndpointError> {
        self.db_context.mark_email_as_verified(user_id, email).await
    }
}

