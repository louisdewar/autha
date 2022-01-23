use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};

use actix_web::web::{self, ServiceConfig};
use tracing::info;

use crate::config::{Config, DynamicProviderConfig};

use super::{
    context::ProviderContext, dynamic::DynamicAuthenticationProvider, AuthenticationProvider,
};

type BoxBuilderFn = Box<
    dyn Fn(
        web::Data<ProviderContext>,
        DynamicProviderConfig,
    ) -> Pin<Box<dyn Future<Output = Arc<dyn DynamicAuthenticationProvider>> + Send>>,
>;

pub struct ProviderManagerBuilder {
    providers: HashMap<String, BoxBuilderFn>,
}

impl ProviderManagerBuilder {
    pub fn new() -> ProviderManagerBuilder {
        ProviderManagerBuilder {
            providers: HashMap::new(),
        }
    }

    pub fn add_provider<Provider: AuthenticationProvider>(&mut self) {
        assert!(
            self.providers
                .insert(
                    Provider::PLUGIN_NAME.to_string(),
                    Box::new(<Provider as DynamicAuthenticationProvider>::build)
                )
                .is_none(),
            "Tried to create two providers with the same name"
        );
    }

    pub async fn build(
        self,
        provider_context: web::Data<ProviderContext>,
        config: &Config,
    ) -> ProviderManager {
        let mut providers = HashMap::with_capacity(config.providers.len());
        for provider_config in &config.providers {
            let plugin = provider_config
                .get("plugin")
                .expect("provider configuration missing plugin")
                .as_str()
                .expect("plugin must be a string");
            let name = provider_config
                .get("name")
                .expect("provider configuration missing name")
                .as_str()
                .expect("provider name must be a string");
            let build_fn = self
                .providers
                .get(plugin)
                .unwrap_or_else(|| panic!("there is no provider with that name (`{}`)", name));

            info!(provider_name = %name, plugin_name = %plugin, "Built provider");

            providers.insert(
                name.to_string(),
                build_fn(provider_context.clone(), provider_config.clone()).await,
            );
        }

        ProviderManager {
            provider_context,
            providers: Arc::new(providers),
        }
    }
}

pub struct ProviderManager {
    providers: Arc<HashMap<String, Arc<dyn DynamicAuthenticationProvider>>>,
    provider_context: web::Data<ProviderContext>,
}

impl ProviderManager {
    pub fn configure_provider_routes(
        &self,
    ) -> impl FnOnce(&mut ServiceConfig) + Clone + Send + Sync {
        let providers = self.providers.clone();
        let provider_context = self.provider_context.clone();
        move |config| {
            config.app_data(provider_context.clone());
            for (name, provider) in providers.iter() {
                config.service(
                    web::scope(&format!("/provider/{}", name)).configure(|config| {
                        DynamicAuthenticationProvider::configure_routes(provider.clone(), config)
                    }),
                );
            }
        }
    }
}
