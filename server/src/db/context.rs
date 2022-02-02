use actix_web::web;
use diesel::PgConnection;
use serde_json::Value;

use crate::{
    error::{database::QueryError, user::UsernameOrEmailExists, DynamicEndpointError},
    jwt::TOKEN_GENERATION_LEN,
};

use super::{
    model::{NewUser, PasswordAuth, User},
    was_unique_key_violation, PgPool,
};

pub struct DatabaseContext {
    db_pool: web::Data<PgPool>,
}

impl DatabaseContext {
    pub fn new(db_pool: web::Data<PgPool>) -> Self {
        DatabaseContext { db_pool }
    }

    async fn run_query<
        F: FnOnce(&PgConnection) -> Result<R, QueryError> + Send + 'static,
        R: Send + 'static,
    >(
        &self,
        f: F,
    ) -> Result<R, QueryError> {
        let db_pool = self.db_pool.clone();
        tokio::task::spawn_blocking(move || {
            let connection = db_pool.get()?;
            f(&connection)
        })
        .await?
    }

    pub async fn get_user_by_id(&self, user_id: i32) -> Result<Option<User>, DynamicEndpointError> {
        let user = self
            .run_query(move |conn| Ok(super::actions::get_user_by_id(conn, user_id)?))
            .await?;

        Ok(user)
    }

    pub async fn mark_email_as_verified(
        &self,
        user_id: i32,
        email: String,
    ) -> Result<User, DynamicEndpointError> {
        let user = self
            .run_query(move |conn| {
                Ok(super::actions::mark_email_as_verified(
                    conn, user_id, &email,
                )?)
            })
            .await?;

        Ok(user)
    }

    /// Either creates or overwrites the password auth for the `user_id`.
    pub async fn upsert_password_auth(
        &self,
        user_id: i32,
        hashed_password: String,
        salt: String,
    ) -> Result<PasswordAuth, DynamicEndpointError> {
        let password_auth = self
            .run_query(move |conn| {
                Ok(super::actions::upsert_password_auth(
                    conn,
                    &super::model::PasswordAuth {
                        user_id,
                        hashed_password,
                        salt,
                    },
                )?)
            })
            .await?;

        Ok(password_auth)
    }

    /// Either creates or overwrites the password auth for the `user_id`.
    pub async fn get_password_auth(
        &self,
        user_id: i32,
    ) -> Result<Option<PasswordAuth>, DynamicEndpointError> {
        let password_auth = self
            .run_query(move |conn| Ok(super::actions::get_password_auth(conn, user_id)?))
            .await?;
        Ok(password_auth)
    }

    /// Then this will insert the user into the database, if the username is taken then this will
    /// return an error.
    ///
    /// TODO: separate upsert_user such that on-conflict it updates the extra field
    pub async fn insert_user(
        &self,
        username: String,
        email: String,
        extra: Value,
    ) -> Result<User, DynamicEndpointError> {
        match self
            .run_query(move |conn| {
                Ok(super::actions::insert_user(
                    conn,
                    &NewUser {
                        username,
                        email: Some(email),
                        extra,
                        token_generation: crate::util::generate_base64_url_safe_string(
                            TOKEN_GENERATION_LEN,
                        ),
                    },
                )?)
            })
            .await
        {
            Ok(user) => Ok(user),
            Err(QueryError::Diesel(e)) if was_unique_key_violation(&e) => {
                Err(UsernameOrEmailExists.into())
            }
            Err(e) => Err(e.into()),
        }
    }

    pub async fn get_user_by_username_or_email(
        &self,
        username_or_email: String,
    ) -> Result<Option<User>, DynamicEndpointError> {
        let user = self
            .run_query(move |conn| {
                Ok(super::actions::get_user_by_username_or_email(
                    conn,
                    &username_or_email,
                )?)
            })
            .await?;

        Ok(user)
    }

    pub async fn set_user_admin_status(
        &self,
        user_id: i32,
        admin_status: bool,
    ) -> Result<User, DynamicEndpointError> {
        let user = self
            .run_query(move |conn| {
                Ok(super::actions::set_user_admin_status(
                    conn,
                    user_id,
                    admin_status,
                )?)
            })
            .await?;

        Ok(user)
    }
}
