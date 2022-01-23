use crate::HTTPClient;
use actix_web::{web, Responder};
use serde::{Deserialize, Serialize};

use crate::error::EndpointResult;

use crate::provider::context::ProviderContext;
use crate::provider::AuthenticationProvider;

#[derive(Deserialize, Debug)]
pub struct OpenIDProviderConfig {
    name: String,
    client_id: String,
    client_secret: String,
    default_redirect_url: String,
    discovery_url: String,
    #[serde(default)]
    trust_email_as_verified: bool,
}

#[derive(Deserialize, Debug)]
pub struct DiscoveryInformation {
    token_endpoint: String,
    authorization_endpoint: String,
    userinfo_endpoint: String,
}

#[derive(Deserialize)]
pub struct StartSSOParams {
    callback_url: Option<String>,
    //state: Option<String>,
}

async fn start_sso(
    provider_context: web::Data<ProviderContext>,
    provider: web::Data<OpenIDProvider>,
    params: web::Json<StartSSOParams>,
) -> EndpointResult<impl Responder> {
    let params = params.into_inner();

    Ok(format!("{:?}", provider.config))
}

pub struct OpenIDProvider {
    config: OpenIDProviderConfig,
    discovery_info: DiscoveryInformation,
}

impl OpenIDProviderConfig {
    async fn discover(&self, http: &HTTPClient) -> DiscoveryInformation {
        let discovery = http
            .get(&self.discovery_url)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        discovery
    }
}

#[async_trait::async_trait]
impl AuthenticationProvider for OpenIDProvider {
    type AuthenticationConfig = OpenIDProviderConfig;

    const PLUGIN_NAME: &'static str = "builtin::openid_connect";

    async fn build(
        context: web::Data<ProviderContext>,
        config: Self::AuthenticationConfig,
    ) -> Self {
        let discovery_info = config.discover(context.http_client()).await;
        dbg!(&discovery_info);
        OpenIDProvider {
            config,
            discovery_info,
        }
    }

    fn configure_flows(&self, config: &mut actix_web::web::ServiceConfig) {
        config.route("start_sso", web::post().to(start_sso));
    }
}
