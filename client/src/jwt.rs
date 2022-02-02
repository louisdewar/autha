use std::borrow::Cow;

use jsonwebtoken::{DecodingKey, TokenData, Validation};
use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::{
    error::{AuthaError, DecodeTokenError, RequestError, VerifyAccessTokenError},
    Client,
};

pub struct JwtInfo {
    jwt_decoding_secret: DecodingKey<'static>,
    aud: String,
}

#[derive(Deserialize)]
struct JwtInfoResponse {
    jwt_decoding_secret: String,
    aud: String,
}

impl JwtInfo {
    pub(crate) async fn get(
        http: &crate::request::HttpClient,
        autha_endpoint: Url,
    ) -> Result<Self, RequestError> {
        let mut url = autha_endpoint;
        url.path_segments_mut().unwrap().extend(["jwt", "info"]);
        let jwt_info: JwtInfoResponse = http.request(http.post(url)).await?.unwrap();

        Ok(JwtInfo {
            jwt_decoding_secret: DecodingKey::from_secret(jwt_info.jwt_decoding_secret.as_bytes())
                .into_static(),
            aud: jwt_info.aud,
        })
    }
}

#[derive(PartialEq, Clone, Debug)]
pub enum Scope<'a> {
    Access,
    Refresh,
    Admin,
    Custom(Cow<'a, str>),
}

impl From<String> for Scope<'static> {
    fn from(s: String) -> Self {
        match s.as_str() {
            "access" => Self::Access,
            "refresh" => Self::Refresh,
            "admin" => Self::Admin,
            _ => Self::Custom(s.into()),
        }
    }
}

#[derive(Debug)]
pub struct Token {
    user_id: i32,
    scopes: Vec<Scope<'static>>,
}

impl Token {
    pub fn user(&self) -> i32 {
        self.user_id
    }

    pub fn has_scope<'a>(&self, scope: &Scope<'a>) -> bool {
        self.scopes.iter().any(|token_scope| token_scope == scope)
    }
}

impl From<SerializableToken> for Token {
    fn from(st: SerializableToken) -> Self {
        Token {
            user_id: st.user_id,
            scopes: st.scopes.into_iter().map(Scope::from).collect(),
        }
    }
}

#[derive(Deserialize, Serialize)]
struct SerializableToken {
    user_id: i32,
    aud: String,
    scopes: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AuthorizeResponse {
    pub access_token: String,
}

#[derive(Debug, Deserialize)]
pub struct IssueRefreshResponse {
    pub refresh_token: String,
}

impl Client {
    fn decode_token(&self, token: &str) -> Result<SerializableToken, VerifyAccessTokenError> {
        let mut validation = Validation::default();
        validation.set_audience(&[&self.jwt_info.aud]);

        let decoded_token: TokenData<SerializableToken> =
            jsonwebtoken::decode(token, &self.jwt_info.jwt_decoding_secret, &validation)
                .map_err(DecodeTokenError::from)?;

        Ok(decoded_token.claims)
    }

    pub fn verify_jwt(&self, token: &str) -> Result<Token, VerifyAccessTokenError> {
        let raw_token = self.decode_token(token)?;

        Ok(raw_token.into())
    }

    pub async fn authorize(
        &self,
        refresh_token: String,
    ) -> Result<Result<AuthorizeResponse, AuthaError>, RequestError> {
        #[derive(Serialize)]
        struct AuthorizeRequest {
            refresh_token: String,
        }

        let mut url = self.autha_endpoint.clone();
        url.path_segments_mut()
            .unwrap()
            .extend(&["jwt", "authorize"]);
        let request = self
            .http
            .post(url)
            .json(&AuthorizeRequest { refresh_token });

        self.http.request(request).await
    }

    pub async fn issue_refresh_token(
        &self,
        user_id: i32,
    ) -> Result<Result<IssueRefreshResponse, AuthaError>, RequestError> {
        #[derive(Serialize)]
        struct IssueRefreshRequest {
            user_id: i32,
        }

        let mut url = self.autha_endpoint.clone();
        url.path_segments_mut()
            .unwrap()
            .extend(&["jwt", "issue_refresh"]);
        let request = self.http.post(url).json(&IssueRefreshRequest { user_id });

        self.http.request(request).await
    }

    pub async fn make_admin(&self, user_id: i32) -> Result<Result<(), AuthaError>, RequestError> {
        #[derive(Serialize)]
        struct MakeAdminRequest {
            user_id: i32,
        }

        let mut url = self.autha_endpoint.clone();
        url.path_segments_mut()
            .unwrap()
            .extend(&["jwt", "permission", "make_admin"]);
        let request = self.http.post(url).json(&MakeAdminRequest { user_id });
        Ok(self
            .http
            .request::<serde_json::Value>(request)
            .await?
            .map(|_| ()))
    }
}
