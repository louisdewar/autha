use diesel::r2d2;
use tokio::task::JoinError;
use crate::{error::DieselError, impl_endpoint_error};

use derive_more::{From, Error, Display};
#[derive(From, Error, Display, Debug)]
pub enum QueryError {
    Pool(r2d2::PoolError),
    Join(JoinError),
    Diesel(DieselError)
}

impl_endpoint_error!(QueryError, INTERNAL_SERVER_ERROR, "INTERNAL_SERVER_ERROR");
