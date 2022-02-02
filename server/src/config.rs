use std::path::Path;

use serde::Deserialize;

use crate::{
    email::{EmailClientConfig, EmailVerificationSettings},
    jwt::JWTConfig,
};

pub type DynamicProviderConfig = serde_json::Value;

#[derive(Deserialize)]
pub struct Config {
    pub shared_secret: String,
    pub instance_id: String,
    #[serde(default)]
    pub email_smtp: Option<EmailClientConfig>,
    #[serde(default)]
    pub email_verify: EmailVerificationSettings,
    pub providers: Vec<DynamicProviderConfig>,
    pub jwt: JWTConfig,
}

impl Config {
    pub async fn load_config<P: AsRef<Path>>(path: P) -> Self {
        let config = tokio::fs::read_to_string(path)
            .await
            .expect("failed to read config file");
        toml::from_str(&config).expect("invalid format for config file")
    }
}
