use std::time::Duration;

use deadpool_redis::redis::{AsyncCommands, RedisError};
use serde::{Serialize, Deserialize};

use super::RedisConnection;

const EMAIL_VERIFY_KEY_BASE: &str = "EMAILVERIFY_";

// What about if a user starts multiple verification attempts, this will cancel the previous
// verification.
// TODO: allow multiple concurrent verifications with individual expirations
fn email_verify_key(verification_code: &str) -> String {
    format!("{EMAIL_VERIFY_KEY_BASE}{verification_code}")
}

#[derive(Serialize, Deserialize)]
pub struct VerificationCodeMeta {
    pub user_id: i32,
    pub email: String,
} 

pub async fn set_email_verification(
    conn: &mut RedisConnection,
    user_id: i32,
    email: String,
    verification_code: &str,
    expires: Duration,
) -> Result<(), RedisError> {
    let key = email_verify_key(verification_code);
    let meta = VerificationCodeMeta {
        user_id,
        email,
    };
    conn.set(&key, serde_json::to_string(&meta).unwrap()).await?;
    conn.expire(&key, expires.as_secs() as usize).await?;

    Ok(())
}

pub async fn find_email_verification(
    conn: &mut RedisConnection,
    verification_code: &str,
) -> Result<Option<VerificationCodeMeta>, RedisError> {
    let key = email_verify_key(verification_code);

    let meta: Option<String> = conn.get(key).await?;

    Ok(meta.map(|meta| serde_json::from_str(&meta).expect("failed to deserialize verification meta")))
}
