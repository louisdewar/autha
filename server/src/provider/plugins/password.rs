use actix_web::web;
use serde::Deserialize;

mod error;
mod request;
mod response;
mod route;
mod util;

use crate::provider::{context::ProviderContext, AuthenticationProvider};

#[derive(Deserialize)]
pub struct PasswordProviderConfig {
    #[serde(default)]
    allowed_email_domains: Option<Vec<String>>,
}

pub struct PasswordProvider {
    config: PasswordProviderConfig,
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
        config.route("register", web::post().to(route::register));
        config.route("login", web::post().to(route::login));
    }
}
