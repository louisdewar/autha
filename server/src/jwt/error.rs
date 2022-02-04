use crate::impl_endpoint_error;

use derive_more::{Display, Error, From};

#[derive(Display, Error, Debug)]
enum VerifyJwtError {
    DecodeHeader(jsonwebtoken::errors::Error),
    DecodeVerifyToken(jsonwebtoken::errors::Error),
}

impl_endpoint_error!(
    VerifyJwtError,
    BAD_REQUEST,
    "INVALID_TOKEN",
    "Please log out and back in again"
);

#[derive(Display, Error, Debug, From)]
pub struct EncodeAccessTokenError {
    source: jsonwebtoken::errors::Error,
}

impl_endpoint_error!(
    EncodeAccessTokenError,
    INTERNAL_SERVER_ERROR,
    "INTERNAL_SERVER_ERROR"
);

#[derive(Display, Error, Debug, From)]
pub struct EncodeRefreshTokenError {
    source: jsonwebtoken::errors::Error,
}

impl_endpoint_error!(
    EncodeRefreshTokenError,
    INTERNAL_SERVER_ERROR,
    "INTERNAL_SERVER_ERROR"
);

#[derive(Display, Error, Debug, From)]
pub struct DecodeTokenError {
    source: jsonwebtoken::errors::Error,
}

impl_endpoint_error!(DecodeTokenError, UNAUTHORIZED, "INVALID_TOKEN");

#[derive(Display, Error, Debug, From)]
pub struct NotRefreshToken;

impl_endpoint_error!(NotRefreshToken, UNAUTHORIZED, "INVALID_TOKEN");

#[derive(Display, Error, Debug, From)]
pub struct NotAccessToken;

impl_endpoint_error!(NotAccessToken, UNAUTHORIZED, "INVALID_TOKEN");

#[derive(Display, Error, Debug, From)]
pub struct MissingTokenGeneration;

impl_endpoint_error!(MissingTokenGeneration, UNAUTHORIZED, "INVALID_TOKEN");

#[derive(Display, Error, Debug, From)]
pub struct MismatchingTokenGeneration;

impl_endpoint_error!(
    MismatchingTokenGeneration,
    UNAUTHORIZED,
    "INVALID_TOKEN",
    "This session has been expired, please login again"
);

#[derive(Display, Error, Debug, From)]
pub struct UserNotAdmin;

impl_endpoint_error!(
    UserNotAdmin,
    UNAUTHORIZED,
    "INVALID_TOKEN",
    "This session has been expired, please login again"
);

#[derive(Display, Error, Debug, From)]
pub struct MissingAuthorizationHeader;
impl_endpoint_error!(
    MissingAuthorizationHeader,
    UNAUTHORIZED,
    "MISSING_TOKEN",
    "You need to be logged in"
);

#[derive(Display, Error, Debug, From)]
pub struct InvalidAuthorizationHeader;
impl_endpoint_error!(
    InvalidAuthorizationHeader,
    UNAUTHORIZED,
    "INVALID_TOKEN",
    "You need to be logged in"
);
