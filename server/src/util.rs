use crate::error::{
    username::{InvalidCharacters, InvalidStartCharacter, UsernameTooLong, UsernameTooShort},
    EndpointError,
};

pub fn default_true() -> bool {
    true
}

pub fn validate_username(username: &str) -> Result<(), Box<dyn EndpointError>> {
    if username.len() > 15 {
        return Err(UsernameTooLong.into());
    }

    if username.len() < 4 {
        return Err(UsernameTooShort.into());
    }

    // First character must be alphabetic
    if !username.chars().next().unwrap().is_ascii_alphabetic() {
        return Err(InvalidStartCharacter.into());
    }

    if username
        .chars()
        .any(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-'))
    {
        return Err(InvalidCharacters.into());
    }

    Ok(())
}

pub fn generate_base64_string(len: usize) -> String {
    use rand::Rng;

    let salt: Vec<u8> = rand::thread_rng()
        .sample_iter(rand::distributions::Standard)
        .take(len)
        .collect();

    base64::encode(salt)
}

pub fn generate_base64_url_safe_string(len: usize) -> String {
    use rand::Rng;

    let salt: Vec<u8> = rand::thread_rng()
        .sample_iter(rand::distributions::Standard)
        .take(len)
        .collect();
    base64::encode_config(salt, base64::URL_SAFE_NO_PAD)
}
