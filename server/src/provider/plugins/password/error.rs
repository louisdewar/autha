use derive_more::{Display, Error};

use crate::impl_endpoint_error;

#[derive(Display, Error, Debug)]
pub struct InvalidPassword;

impl_endpoint_error!(
    InvalidPassword,
    BAD_REQUEST,
    "INVALID_PASSWORD",
    "The password fails to meet basic requirements"
);

#[derive(Display, Error, Debug)]
pub struct PasswordAuthNotEnabled;

impl_endpoint_error!(
    PasswordAuthNotEnabled,
    BAD_REQUEST,
    "PASSWORD_AUTH_NOT_ENABLED",
    "Password auth is not enabled for this account"
);

#[derive(Display, Error, Debug)]
pub struct IncorrectCredentials;

impl_endpoint_error!(
    IncorrectCredentials,
    BAD_REQUEST,
    "INCORRECT_CREDENTIALS",
    "The username or password is incorrect"
);
