use actix_web::web;
use reqwest::Url;
use serde::Deserialize;
use tera::Tera;

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
    reset_url: String,
    reset_template: String,
}

pub struct PasswordProvider {
    config: PasswordProviderConfig,
    tera: Tera,
    reset_url: Url,
}

#[async_trait::async_trait]
impl AuthenticationProvider for PasswordProvider {
    type AuthenticationConfig = PasswordProviderConfig;

    const PLUGIN_NAME: &'static str = "builtin::password";

    async fn build(
        _context: web::Data<ProviderContext>,
        config: Self::AuthenticationConfig,
    ) -> Self {
        let mut tera = Tera::default();

        tera.add_raw_template("reset_password_email", &config.reset_template)
            .expect("invalid reset password template");

        let reset_url = config.reset_url.parse().expect("invalid reset URL");

        PasswordProvider {
            config,
            tera,
            reset_url,
        }
    }

    fn configure_flows(&self, config: &mut actix_web::web::ServiceConfig) {
        config.route("register", web::post().to(route::register));
        config.route("login", web::post().to(route::login));
        config.route("change_password", web::post().to(route::change_password));
    }
}
