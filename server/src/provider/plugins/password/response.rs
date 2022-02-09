use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum PasswordProviderIncompleteFlow {
    ResetPasswordEmailSent,
    PasswordChanged,
    PasswordReset,
}
