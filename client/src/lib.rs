use error::StartupError;
use jwt::JwtInfo;
use request::HttpClient;
use reqwest::Url;

pub mod email;
pub mod error;
pub mod flow;
pub mod jwt;
pub mod request;

pub struct Client {
    http: HttpClient,
    autha_endpoint: Url,
    jwt_info: JwtInfo,
}

impl Client {
    pub async fn new(autha_endpoint: Url, shared_secret: String) -> Result<Self, StartupError> {
        assert!(
            !autha_endpoint.cannot_be_a_base(),
            "autha endpoint must be a base URL"
        );

        let http = HttpClient::new(shared_secret);
        let jwt_info = JwtInfo::get(&http, autha_endpoint.clone())
            .await
            .map_err(StartupError::Jwt)?;

        Ok(Client {
            http,
            autha_endpoint,
            jwt_info,
        })
    }
}
