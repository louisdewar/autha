use crate::db::schema::*;
use serde::Serialize;
use serde_json::Value;

#[derive(Queryable, Serialize)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub extra: Value,
}

#[derive(Insertable)]
#[table_name = "users"]
pub struct NewUser {
    pub username: String,
    pub email: Option<String>,
    pub extra: Value,
}

#[derive(Insertable, Queryable, AsChangeset)]
#[table_name = "password_auth"]
pub struct PasswordAuth {
    pub user_id: i32,
    pub hashed_password: String,
    pub salt: String,
}
