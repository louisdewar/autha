use std::sync::Arc;

use actix_web::web::{self, ServiceConfig};

use crate::config::DynamicProviderConfig;

use super::{context::ProviderContext, AuthenticationProvider};

#[async_trait::async_trait]
pub trait DynamicAuthenticationProvider: Send + Sync {
    async fn build(
        context: web::Data<ProviderContext>,
        config: DynamicProviderConfig,
    ) -> Arc<dyn DynamicAuthenticationProvider>
    where
        Self: Sized;

    fn configure_routes(self: Arc<Self>, config: &mut ServiceConfig);
}

#[async_trait::async_trait]
impl<Provider: AuthenticationProvider> DynamicAuthenticationProvider for Provider {
    fn configure_routes(self: Arc<Self>, config: &mut ServiceConfig) {
        config.app_data(web::Data::from(self.clone()));
        config
            .service(web::scope("f").configure(|config| {
                AuthenticationProvider::configure_flows(self.as_ref(), config)
            }));
    }

    async fn build(
        context: web::Data<ProviderContext>,
        config: DynamicProviderConfig,
    ) -> Arc<dyn DynamicAuthenticationProvider> {
        let provider: Provider =
            AuthenticationProvider::build(context, serde_json::from_value(config).unwrap()).await;
        Arc::new(provider)
    }
}
