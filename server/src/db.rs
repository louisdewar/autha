//use bb8::Pool;
//use bb8_diesel::DieselConnectionManager;
use diesel::{
    r2d2::{self, ConnectionManager, Pool},
    PgConnection,
};

pub mod actions;
mod context;
pub mod model;
mod schema;

pub use context::DatabaseContext;

embed_migrations!();

pub fn run_migrations(connection: &PgConnection) {
    embedded_migrations::run_with_output(connection, &mut std::io::stdout())
        .expect("Failed to run migrations");
}

pub fn was_unique_key_violation(error: &crate::error::DieselError) -> bool {
    matches!(
        error,
        crate::error::DieselError::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _
        ),
    )
}

pub type PgPool = r2d2::Pool<ConnectionManager<PgConnection>>;
//pub type DBPool = Pool<DieselConnectionManager<PgConnection>>;

pub async fn get_pg_pool(database_url: &str) -> PgPool {
    /*let manager = bb8_diesel::DieselConnectionManager::<PgConnection>::new("localhost:1234");
    let pool = bb8::Pool::builder().build(manager).await.unwrap();
    pool*/
    //let conn = pool.get().await.unwrap();
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    Pool::builder()
        .build(manager)
        .expect("Failed to create DB pool")
}
