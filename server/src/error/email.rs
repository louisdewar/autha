use crate::impl_endpoint_error;
use derive_more::{Display, Error, From};
use lettre::{address::AddressError, transport::smtp};

impl_endpoint_error!(smtp::Error, INTERNAL_SERVER_ERROR, "INTERNAL_SERVER_ERROR");

#[derive(From, Error, Display, Debug)]
pub struct AddressParseError {
    source: AddressError,
}

impl_endpoint_error!(
    AddressParseError,
    BAD_REQUEST,
    "INVALID_EMAIL_ADDRESS",
    "The provided email address is invalid"
);

#[derive(From, Error, Display, Debug)]
pub struct DomainNotAllowed;

impl_endpoint_error!(
    DomainNotAllowed,
    BAD_REQUEST,
    "INVALID_EMAIL_DOMAIN",
    "This email is not from an approved organization"
);

#[derive(From, Error, Display, Debug)]
pub struct NoEmail;

impl_endpoint_error!(
    NoEmail,
    BAD_REQUEST,
    "NO_EMAIL",
    "There is no email associated with this account"
);

#[derive(From, Error, Display, Debug)]
pub struct InvalidVerificationCode;

impl_endpoint_error!(
    InvalidVerificationCode,
    BAD_REQUEST,
    "INVALID_VERIFICATION_CODE",
    "This verification code is incorrect or has expired, please try verifying your email again."
);

#[derive(From, Error, Display, Debug)]
pub struct InvalidVerificationTemplate {
    source: tera::Error,
}

impl_endpoint_error!(
    InvalidVerificationTemplate,
    INTERNAL_SERVER_ERROR,
    "INTERNAL_SERVER_ERROR"
);
