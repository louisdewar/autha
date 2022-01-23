use derive_more::{Display, Error};

use crate::impl_endpoint_error;

#[derive(Display, Error, Debug)]
pub struct UserNotFound;

impl_endpoint_error!(
    UserNotFound,
    NOT_FOUND,
    "USER_NOT_FOUND",
    "No user with that username exists"
);

#[derive(Display, Error, Debug)]
pub struct UsernameOrEmailExists;

impl_endpoint_error!(
    UsernameOrEmailExists,
    BAD_REQUEST,
    "BAD_REQUEST",
    "A user with that email or username already exists"
);
