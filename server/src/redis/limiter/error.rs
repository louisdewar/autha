use derive_more::{Display, Error, From};
use redis::RedisError;

use crate::impl_endpoint_error;

#[derive(Debug, Display, Error, From)]
pub enum GetLimiterPermitError {
    Redis(RedisError),
    RedisPool(deadpool_redis::PoolError),
}

impl_endpoint_error!(
    GetLimiterPermitError,
    INTERNAL_SERVER_ERROR,
    "INTERNAL_SERVER_ERROR"
);

#[derive(Debug, Display, Error)]
pub struct RateLimitReached {
    /// Time until the next permit is available.
    pub ttl: u64,
}

#[macro_export]
macro_rules! create_rate_limit_error {
    ($name:ident, $error_message:expr) => {
        #[derive(Debug, derive_more::Display, derive_more::Error, derive_more::From)]
        pub struct $name {
            source: $crate::redis::limiter::error::RateLimitReached,
        }

        impl $crate::error::EndpointError for $name {
            fn error_code(&self) -> String {
                "NO_PERMITS".into()
            }

            fn error_message(&self) -> Option<String> {
                let message: Option<_> = $error_message.into();

                message.map(|inner| inner.into())
            }

            fn status(&self) -> actix_web::http::StatusCode {
                actix_web::http::StatusCode::TOO_MANY_REQUESTS
            }

            // fn inject_headers(&self, builder: &mut doxa_core::error::HttpResponseBuilder) {
            //     builder.insert_header((actix_web::http::header::RETRY_AFTER, self.source.ttl));
            // }
        }
    };
}
