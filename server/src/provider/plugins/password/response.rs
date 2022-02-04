use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PasswordProviderIncompleteFlow {
    ResetPasswordEmailSent,
    PasswordChanged,
    PasswordReset,
}
