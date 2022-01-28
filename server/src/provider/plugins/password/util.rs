use crate::util::generate_base64_url_safe_string;

const SALT_BYTES_LEN: usize = 16;
const ROUNDS: u32 = 50;
const HASH_SIZE_BYTES: usize = 32;
const MAX_PASSWORD_LEN: usize = 256;

pub fn hash_password(password: &str, salt: &str) -> String {
    let mut output = vec![0; HASH_SIZE_BYTES];
    bcrypt_pbkdf::bcrypt_pbkdf(
        password,
        &base64::decode(salt).expect("salt was not base64"),
        ROUNDS,
        &mut output,
    )
    .expect("bcrypt failed!");
    base64::encode(output)
}

pub fn generate_salt() -> String {
    generate_base64_url_safe_string(SALT_BYTES_LEN)
}

pub fn verify(password: &str, hashed_password: &str, salt: &str) -> bool {
    let salt = base64::decode(salt).expect("Salt was not base64");
    let hashed_password = base64::decode(hashed_password).expect("hashed password was not base64");

    let mut output = vec![0; HASH_SIZE_BYTES];
    bcrypt_pbkdf::bcrypt_pbkdf(password, &salt, ROUNDS, &mut output).expect("bcrypt failed!");
    output == hashed_password
}

/// Checks if the password meets basic requirements, in future use something like zxcvbn.
pub fn validate_password(password: &str) -> bool {
    password.len() > 5 && password.len() < MAX_PASSWORD_LEN
}
