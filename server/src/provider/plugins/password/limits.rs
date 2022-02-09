use std::{sync::Arc, time::Duration};

use crate::redis::limiter::{
    GenericLimiter, Limiter, LimiterConfig, TokenBucket, ONE_DAY, ONE_HOUR,
};

const RESET_PASSWORD_LIMITER_ID: &str = "RESETPASSWORD";

pub struct PasswordProviderLimits {
    /// Rate limits reset password emails
    pub reset_password: Limiter,
}

impl PasswordProviderLimits {
    pub fn new(generic: Arc<GenericLimiter>) -> Self {
        PasswordProviderLimits {
            reset_password: login_attempts_limiter().build(&generic),
        }
    }
}

fn login_attempts_limiter() -> LimiterConfig {
    let mut limiter = LimiterConfig::new(RESET_PASSWORD_LIMITER_ID.into());

    limiter
        // 2 per 5 minutes
        .add_limit(TokenBucket::new(Duration::from_secs(60) * 5, 2))
        // 10 per hour
        .add_limit(TokenBucket::new(ONE_HOUR, 10))
        // 20 per day
        .add_limit(TokenBucket::new(ONE_DAY, 30));

    limiter
}
