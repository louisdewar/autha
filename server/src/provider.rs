use actix_web::web::{self, ServiceConfig};
use serde::de::DeserializeOwned;

mod context;
mod dynamic;
pub mod flow;
pub mod manager;

pub mod plugins;

// Provider implementations
// pub mod openid_connect;
// pub mod password;

pub use context::ProviderContext;
pub use manager::ProviderManager;

use async_trait::async_trait;

use crate::config::Config;

use self::{
    manager::ProviderManagerBuilder,
    plugins::{OpenIDProvider, PasswordProvider},
};

#[async_trait]
pub trait AuthenticationProvider: Sized + 'static + Send + Sync {
    type AuthenticationConfig: DeserializeOwned + Send;

    const PLUGIN_NAME: &'static str;

    async fn build(context: web::Data<ProviderContext>, config: Self::AuthenticationConfig)
        -> Self;

    fn configure_flows(&self, config: &mut ServiceConfig);
}

pub async fn setup_providers(
    provider_context: web::Data<ProviderContext>,
    config: &Config,
) -> ProviderManager {
    let mut builder = ProviderManagerBuilder::new();
    builder.add_provider::<OpenIDProvider>();
    builder.add_provider::<PasswordProvider>();

    builder.build(provider_context, config).await
}
