use std::time::Duration;

use deadpool_redis::redis::{AsyncCommands, RedisError};
use serde::{Deserialize, Serialize};

use crate::redis::RedisConnection;

const PASSWORD_RESET_KEY_BASE: &str = "PASSWORDRESET_";

fn password_reset_key(verification_code: &str) -> String {
    format!("{PASSWORD_RESET_KEY_BASE}{verification_code}")
}

#[derive(Serialize, Deserialize)]
pub struct PasswordResetMeta {
    pub user_id: i32,
    pub old_password_hash: String,
}

pub async fn set_password_reset(
    conn: &mut RedisConnection,
    user_id: i32,
    old_password_hash: String,
    verification_code: &str,
    expires: Duration,
) -> Result<(), RedisError> {
    let key = password_reset_key(verification_code);
    let meta = PasswordResetMeta {
        user_id,
        old_password_hash,
    };
    conn.set(&key, serde_json::to_string(&meta).unwrap())
        .await?;
    conn.expire(&key, expires.as_secs() as usize).await?;

    Ok(())
}

/// Finds and deletes the password reset record (if it exists).
pub async fn take_password_reset(
    conn: &mut RedisConnection,
    verification_code: &str,
) -> Result<Option<PasswordResetMeta>, RedisError> {
    let key = password_reset_key(verification_code);

    let meta: Option<String> = conn.get(&key).await?;
    conn.del(&key).await?;

    Ok(meta
        .map(|meta| serde_json::from_str(&meta).expect("failed to deserialize verification meta")))
}
