use derive_more::{Display, Error};

use crate::impl_endpoint_error;

#[derive(Error, Display, Debug)]
pub struct UsernameTooLong;

impl_endpoint_error!(
    UsernameTooLong,
    BAD_REQUEST,
    "USERNAME_TOO_LONG",
    "The username is too long"
);

#[derive(Error, Display, Debug)]
pub struct UsernameTooShort;

impl_endpoint_error!(
    UsernameTooShort,
    BAD_REQUEST,
    "USERNAME_TOO_SHORT",
    "The username is too short"
);

#[derive(Error, Display, Debug)]
pub struct InvalidCharacters;

impl_endpoint_error!(
    InvalidCharacters,
    BAD_REQUEST,
    "USERNAME_INVALID_CHARACTERS",
    "There are invalid characters in the username"
);

#[derive(Error, Display, Debug)]
pub struct InvalidStartCharacter;

impl_endpoint_error!(
    InvalidStartCharacter,
    BAD_REQUEST,
    "USERNAME_INVALID_START_CHARACTERS",
    "Usernames must begin with a letter"
);
