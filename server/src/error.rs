use actix_web::{
    body::BoxBody, http::StatusCode, HttpResponse, HttpResponseBuilder, Responder, ResponseError,
};
use deadpool_redis::redis::RedisError;
use diesel::r2d2;
use serde::Serialize;
use tokio::task::JoinError;

pub type DynamicEndpointError = Box<dyn EndpointError>;
pub type EndpointResult<T = HttpResponse> = Result<T, DynamicEndpointError>;

pub mod email;
pub mod user;
pub mod username;
pub mod database;


pub use diesel::result::Error as DieselError;

#[derive(Serialize)]
struct InnerErrorResponse {
    error: String,
    error_message: Option<String>,
}

pub trait EndpointError: std::error::Error + Send + Sync + 'static {
    fn status(&self) -> StatusCode;
    fn error_code(&self) -> String;
    fn error_message(&self) -> Option<String>;

    fn http_response(&self) -> HttpResponse<BoxBody> {
        let status = self.status();
        let inner = InnerErrorResponse {
            error: self.error_code(),
            error_message: self.error_message(),
        };

        HttpResponseBuilder::new(status).json(inner)
    }
}

impl<T: EndpointError> From<T> for DynamicEndpointError {
    fn from(e: T) -> Self {
        Box::new(e)
    }
}

impl Responder for DynamicEndpointError {
    type Body = BoxBody;

    fn respond_to(self, _req: &actix_web::HttpRequest) -> HttpResponse<Self::Body> {
        self.http_response()
    }
}

impl ResponseError for Box<dyn EndpointError> {
    fn status_code(&self) -> StatusCode {
        self.status()
    }

    fn error_response(&self) -> HttpResponse<BoxBody> {
        self.http_response()
    }
}

// impl<'r> Responder<'r, 'static> for Box<dyn EndpointError> {
//     fn respond_to(self, req: &'r Request<'_>) -> response::Result<'static> {

//         let status = self.status();
//         let inner = InnerErrorResponse {
//             error: self.error_code(),
//             error_message: self.error_message(),
//         };

//         let string = serde_json::to_string(&inner)
//             .map_err(|e| {
//                 error_!("JSON failed to serialize: {:?}", e);
//                 Status::InternalServerError
//             })?;

//         content::Json(string).respond_to(req).map(|mut res| {
//             res.set_status(status);
//             res
//         })
//     }
// }

#[macro_export]
macro_rules! impl_endpoint_error {
    ($struct:ty, $status:ident, $error:expr, message: $error_message:expr) => {
        impl $crate::error::EndpointError for $struct {
            fn status(&self) -> actix_web::http::StatusCode {
                actix_web::http::StatusCode::$status
            }

            fn error_code(&self) -> String {
                $error.into()
            }

            fn error_message(&self) -> Option<String> {
                $error_message.into()
            }
        }
    };

    ($struct:ty, $status:ident, $error:expr) => {
        impl_endpoint_error!($struct, $status, $error, message: None);
    };

    ($struct:ty, $status:ident, $error:expr, $error_message:expr) => {
        impl_endpoint_error!($struct, $status, $error, message: Some($error_message.into()));
    };
}

impl_endpoint_error!(JoinError, INTERNAL_SERVER_ERROR, "INTERNAL_SERVER_ERROR");
impl_endpoint_error!(
    deadpool_redis::PoolError,
    INTERNAL_SERVER_ERROR,
    "INTERNAL_SERVER_ERROR"
);
impl_endpoint_error!(
    r2d2::PoolError,
    INTERNAL_SERVER_ERROR,
    "INTERNAL_SERVER_ERROR"
);

impl_endpoint_error!(RedisError, INTERNAL_SERVER_ERROR, "INTERNAL_SERVER_ERROR");
impl_endpoint_error!(DieselError, INTERNAL_SERVER_ERROR, "INTERNAL_SERVER_ERROR");
