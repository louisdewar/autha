use std::collections::HashMap;

use crate::util::generate_base64_url_safe_string;
use crate::HTTPClient;
use crate::{impl_endpoint_error, provider::flow::FlowResponse};
use actix_web::{web, HttpRequest, Responder};
use jsonwebkey::{Algorithm, JsonWebKey};
use jsonwebtoken::{DecodingKey, TokenData, Validation};
use reqwest::Url;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::debug;

use crate::error::EndpointResult;

use crate::provider::context::ProviderContext;
use crate::provider::AuthenticationProvider;

use derive_more::{Display, Error};

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
struct DiscoveryInformation {
    token_endpoint: String,
    authorization_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    issuer: String,
}

#[derive(Deserialize, Debug)]
struct IssuerWebKeys {
    keys: Vec<JsonWebKey>,
}

#[derive(Clone)]
struct OAuthInfo {
    token_endpoint: Url,
    authorization_endpoint: Url,
    userinfo_endpoint: Url,
    client_id: String,
    client_secret: String,
    key_store: IssuerKeyStore,
    issuer: String,
}

#[derive(Deserialize)]
struct StartSSOParams {
    #[serde(default)]
    callback_url: Option<String>,
}

#[derive(Deserialize)]
struct SSOCallbackParams {
    id_token: String,
}

#[derive(Deserialize)]
struct IdTokenClaims {
    email: String,
}

#[derive(Display, Error, Debug)]
enum DecodeJwtError {
    DecodeHeader(jsonwebtoken::errors::Error),
    DecodeVerifyToken(jsonwebtoken::errors::Error),
    MissingKeyID,
    UnknownKey,
}

impl_endpoint_error!(
    DecodeJwtError,
    BAD_REQUEST,
    "INVALID_ID_TOKEN",
    "Your were issued with an invalid token, please try the SSO flow again"
);

#[derive(Clone)]
struct IssuerKeyStore {
    map: HashMap<String, (jsonwebtoken::Algorithm, DecodingKey<'static>)>,
}

impl IssuerKeyStore {
    async fn load(jwk_uri: Url, http: &HTTPClient) -> Self {
        let response: IssuerWebKeys = http
            .get(jwk_uri)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        let map = response
            .keys
            .into_iter()
            .map(|jwk| {
                (
                    jwk.key_id.expect("key did not have ID"),
                    (
                        jwk.algorithm.unwrap_or(Algorithm::RS256).into(),
                        jwk.key.to_decoding_key(),
                    ),
                )
            })
            .collect();

        IssuerKeyStore { map }
    }

    fn decode_jwt<T: DeserializeOwned>(
        &self,
        audience: String,
        issuer: String,
        jwt: String,
    ) -> Result<TokenData<T>, DecodeJwtError> {
        let header = jsonwebtoken::decode_header(&jwt).map_err(DecodeJwtError::DecodeHeader)?;
        // TOOD: header contains alg e.g. RS256, use that to create the validation struct
        let key_id = header.kid.ok_or(DecodeJwtError::MissingKeyID)?;

        let (algorithm, key) = self.map.get(&key_id).ok_or(DecodeJwtError::UnknownKey)?;
        let mut validation = Validation::new(*algorithm);
        validation.aud = Some([audience].into());
        validation.iss = Some(issuer);

        let claims: TokenData<T> = jsonwebtoken::decode(&jwt, key, &validation)
            .map_err(DecodeJwtError::DecodeVerifyToken)?;

        Ok(claims)
    }
}

fn create_authorize_url(oauth: &OAuthInfo, redirect_uri: &str) -> Url {
    let nonce = generate_base64_url_safe_string(16);

    let mut url = oauth.authorization_endpoint.clone();
    url.query_pairs_mut()
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("client_id", &oauth.client_id)
        .append_pair("response_type", "id_token")
        .append_pair("scope", "email+openid+profile")
        .append_pair("nonce", &nonce)
        .append_pair("response_mode", "fragment");

    url
}

#[derive(Deserialize, Serialize)]
struct RegisterField {
    initial_value: String,
    mutatable: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
enum OpenIDConnectIncompleteResponse {
    Redirect {
        url: String,
    },
    Register {
        auth_token: String,
        fields: HashMap<String, RegisterField>,
    },
}

async fn start_sso(
    provider: web::Data<OpenIDProvider>,
    provider_context: web::Data<ProviderContext>,
    params: web::Json<StartSSOParams>,
    req: HttpRequest,
) -> EndpointResult<impl Responder> {
    let params = params.into_inner();
    let redirect_uri = create_authorize_url(
        &provider.oauth_info,
        params
            .callback_url
            .as_ref()
            .unwrap_or(&provider.config.default_redirect_url),
    );

    FlowResponse::Incomplete {
        payload: OpenIDConnectIncompleteResponse::Redirect {
            url: redirect_uri.into(),
        },
    }
    .respond_to(&req, provider_context.as_ref())
    .await
}

async fn sso_callback(
    provider: web::Data<OpenIDProvider>,
    params: web::Json<SSOCallbackParams>,
) -> EndpointResult<impl Responder> {
    let id_token = params.into_inner().id_token;

    let token: TokenData<IdTokenClaims> = provider.oauth_info.key_store.decode_jwt(
        id_token,
        provider.oauth_info.client_id.clone(),
        provider.oauth_info.issuer.clone(),
    )?;

    dbg!(token.claims.email);

    Ok("TODO")
}

pub struct OpenIDProvider {
    oauth_info: OAuthInfo,
    config: OpenIDProviderConfig,
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
        debug!(?discovery_info, provider_name=%config.name, "Loaded OAuth discovery info");

        let key_store = IssuerKeyStore::load(
            discovery_info.jwks_uri.parse().unwrap(),
            context.http_client(),
        )
        .await;

        let oauth_info = OAuthInfo {
            token_endpoint: discovery_info.token_endpoint.parse().unwrap(),
            authorization_endpoint: discovery_info.authorization_endpoint.parse().unwrap(),
            userinfo_endpoint: discovery_info.userinfo_endpoint.parse().unwrap(),
            client_id: config.client_id.clone(),
            client_secret: config.client_secret.clone(),
            key_store,
            issuer: discovery_info.issuer,
        };

        OpenIDProvider { oauth_info, config }
    }

    fn configure_flows(&self, config: &mut actix_web::web::ServiceConfig) {
        config
            .route("start_sso", web::post().to(start_sso))
            .route("sso_callback", web::post().to(sso_callback));
    }
}
