use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};

use crate::{
    error::{user::UserNotFound, DynamicEndpointError},
    provider::ProviderContext,
};
mod error;

use self::error::{
    DecodeTokenError, EncodeAccessTokenError, EncodeRefreshTokenError, MismatchingTokenGeneration,
    MissingTokenGeneration, NotAccessToken, NotRefreshToken, UserNotAdmin,
};

mod extractor;
mod route;

pub use route::configure_routes;

pub const TOKEN_GENERATION_LEN: usize = 10;

const REFRESH_TOKEN_DURATION: Duration = Duration::from_secs(60 * 60 * 24 * 7);
const ACCESS_TOKEN_DURATION: Duration = Duration::from_secs(60 * 60 * 2);

#[derive(Serialize, Deserialize)]
pub struct Token {
    aud: String,
    scopes: Vec<String>,
    user_id: i32,
    #[serde(default)]
    token_generation: Option<String>,
    exp: u64,
}

pub struct RefreshToken {
    user_id: i32,
    admin: bool,
}

pub struct AccessToken {
    user_id: i32,
    admin: bool,
}

impl AccessToken {
    pub fn id(&self) -> i32 {
        self.user_id
    }

    pub fn is_admin(&self) -> bool {
        self.admin
    }
}

#[derive(Deserialize)]
pub struct JWTConfig {
    pub secret: String,
}

#[derive(Clone)]
pub struct JwtSettings {
    pub encoding_key: EncodingKey,
    pub decoding_key: DecodingKey<'static>,
    pub token_aud: String,
}

impl ProviderContext {
    fn decode_token(&self, token: &str) -> Result<Token, DynamicEndpointError> {
        let mut validation = Validation::default();
        validation.set_audience(&[&self.jwt_settings.token_aud]);
        validation.leeway = 4 * 60;

        let decoded_token: TokenData<Token> =
            jsonwebtoken::decode(token, &self.jwt_settings.decoding_key, &validation)
                .map_err(DecodeTokenError::from)?;

        Ok(decoded_token.claims)
    }

    async fn decode_refresh_token(
        &self,
        token: &str,
    ) -> Result<RefreshToken, DynamicEndpointError> {
        let token = self.decode_token(token)?;
        if !token.scopes.iter().any(|scope| scope == "refresh") {
            return Err(NotRefreshToken.into());
        }

        let generation = token.token_generation.ok_or(MissingTokenGeneration)?;
        let user = self
            .get_user_by_id(token.user_id)
            .await?
            .ok_or(UserNotFound)?;

        if user.token_generation != generation {
            return Err(MismatchingTokenGeneration.into());
        }

        let admin_scope = token.scopes.iter().any(|scope| scope == "admin");

        if !user.admin && admin_scope {
            return Err(UserNotAdmin.into());
        }

        Ok(RefreshToken {
            user_id: token.user_id,
            admin: admin_scope,
        })
    }

    pub fn decode_access_token(&self, token: &str) -> Result<AccessToken, DynamicEndpointError> {
        let token = self.decode_token(token)?;
        if !token.scopes.iter().any(|scope| scope == "access") {
            return Err(NotAccessToken.into());
        }

        let admin = token.scopes.iter().any(|scope| scope == "admin");

        Ok(AccessToken {
            user_id: token.user_id,
            admin,
        })
    }

    /// Generates a refresh token for the given user id
    pub async fn generate_refresh_token(
        &self,
        user_id: i32,
    ) -> Result<String, DynamicEndpointError> {
        let user = self.get_user_by_id(user_id).await?.ok_or(UserNotFound)?;

        // Temporarily allow token for access too
        let mut scopes = vec!["refresh".to_string(), "access".to_string()];

        if user.admin {
            scopes.push("admin".to_string());
        }

        let claims = Token {
            aud: self.jwt_settings.token_aud.clone(),
            scopes,
            user_id,
            token_generation: Some(user.token_generation),
            exp: (SystemTime::now() + REFRESH_TOKEN_DURATION)
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or(0),
        };
        let jwt = encode(&Header::default(), &claims, &self.jwt_settings.encoding_key)
            .map_err(EncodeRefreshTokenError::from)?;

        Ok(jwt)
    }

    pub async fn generate_access_token(
        &self,
        refresh_token: &RefreshToken,
    ) -> Result<String, DynamicEndpointError> {
        let mut scopes = vec!["access".to_string()];

        if refresh_token.admin {
            scopes.push("admin".to_string());
        }

        let claims = Token {
            aud: self.jwt_settings.token_aud.clone(),
            scopes,
            user_id: refresh_token.user_id,
            token_generation: None,
            exp: (SystemTime::now() + ACCESS_TOKEN_DURATION)
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or(0),
        };
        let jwt = encode(&Header::default(), &claims, &self.jwt_settings.encoding_key)
            .map_err(EncodeAccessTokenError::from)?;

        Ok(jwt)
    }
}
