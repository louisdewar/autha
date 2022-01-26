use diesel::{ExpressionMethods, OptionalExtension, PgConnection, QueryDsl, RunQueryDsl};

use super::model::{NewUser, PasswordAuth, User};
use super::schema::{password_auth, users};
use crate::error::DieselError;

// use crate::error::EndpointError;
//
// use super::PgPool;
//
// pub type ModelResult<T> = Result<T, Box<dyn EndpointError>>;
// //pub type DBConnection<'a> = PooledConnection<'a, DieselConnectionManager<PgConnection>>;
// //pub type DBConnection = bb8_diesel::DieselConnection<>;
//
// pub struct Model {
//     db_pool: PgPool
// }
//
// impl Model {
//     async fn db_connection(&self) -> ModelResult<impl Deref<Target = PgConnection>> {
//         let pool = self.db_pool.clone();
//         let connection = tokio::task::spawn_blocking(move || pool.get()).await??;
//
//         Ok(connection)
//     }
//     // pub async fn db_connection(&self) -> ModelResult<DBConnection<'static>> {
//     //     let connection = self.db_pool.get().await?;
//
//     //     Ok(connection)
//     // }
//     //pub async fn run_query<F: Fn()>
//
//     pub async fn get_user_by_username(&self) {
//
//     }
// }

pub fn get_user_by_id(conn: &PgConnection, user_id: i32) -> Result<Option<User>, DieselError> {
    users::table
        .filter(users::columns::id.eq(user_id))
        .first(conn)
        .optional()
}

pub fn get_user_by_username_or_email(
    conn: &PgConnection,
    username_or_email: &str,
) -> Result<Option<User>, DieselError> {
    users::table
        .filter(users::columns::username.eq(username_or_email))
        .or_filter(users::columns::email.eq(Some(username_or_email)))
        .first(conn)
        .optional()
}

pub fn insert_user(conn: &PgConnection, user: &NewUser) -> Result<User, DieselError> {
    diesel::insert_into(users::table)
        .values(user)
        .get_result(conn)
}

pub fn mark_email_as_verified(
    conn: &PgConnection,
    user_id: i32,
    email: &str,
) -> Result<User, DieselError> {
    diesel::update(
        users::table
            .filter(users::columns::id.eq(user_id))
            .filter(users::columns::email.eq(email)),
    )
    .set(users::columns::email_verified.eq(true))
    .get_result(conn)
}

pub fn upsert_password_auth(
    conn: &PgConnection,
    password_auth: &PasswordAuth,
) -> Result<PasswordAuth, DieselError> {
    diesel::insert_into(password_auth::table)
        .values(password_auth)
        .on_conflict(password_auth::user_id)
        .do_update()
        .set(password_auth)
        .get_result(conn)
}

pub fn get_password_auth(
    conn: &PgConnection,
    user_id: i32,
) -> Result<Option<PasswordAuth>, DieselError> {
    password_auth::table
        .filter(password_auth::columns::user_id.eq(user_id))
        .first(conn)
        .optional()
}
