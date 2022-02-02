use serde::Deserialize;

#[derive(Deserialize)]
pub struct RegisterParams {
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginParams {
    // Consider only allowing logins by username and keeping email private for backup login methods.
    // We currently leak if a username or email does / does not exist, this isn't important for
    // usernames but probably is for emails.
    pub username_or_email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct ChangePasswordParams {
    pub old_password: String,
    pub new_password: String,
}
