use actix_web::{guard, web, App, HttpServer};
use clap::StructOpt;
use config::Config;
use provider::{setup_providers, ProviderContext};

pub use reqwest::Client as HTTPClient;
use tracing::info;
use tracing_actix_web::TracingLogger;

use crate::db::DatabaseContext;

#[macro_use]
extern crate diesel;
#[macro_use]
extern crate diesel_migrations;

mod cli;
mod config;
mod db;
mod error;
mod provider;
mod redis;
mod telemetry;

pub mod email;
pub mod util;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    telemetry::init_telemetry();

    dotenv::dotenv().expect("failed to load .env");
    let app = cli::App::parse();
    let config = web::Data::new(Config::load_config(&app.config_path).await);

    info!(config_path = %app.config_path, "loaded config");

    // let db_pool = db::get_pg_pool("postgres://autha-dev:autha-dev@localhost:5433/autha").await;

    let db_pool = web::Data::new(db::get_pg_pool(&app.database_url).await);
    info!(url = %app.database_url, "created postgresql database pool");
    let redis_pool = web::Data::new(redis::get_redis_pool(app.redis_url.clone(), 20).await);
    info!(url = %app.redis_url, "created redis database pool");

    db::run_migrations(
        &db_pool
            .get()
            .expect("failed to get db connection to run migrations"),
    );

    let provider_context = web::Data::new(ProviderContext::new(db_pool.clone()));
    let provider_manager = setup_providers(provider_context, &config).await;

    let provider_routes = provider_manager.configure_provider_routes();

    if config.email_verify.enabled && config.email_smtp.is_none() {
        panic!("Email verification enabled but there are no SMTP settings");
    }

    // This could probably be a warning instead of an error (e.g. if an admin temporarily disables
    // verification).
    if !config.email_verify.allow_login_before_verification && !config.email_verify.enabled {
        panic!("Users must have their emails verified before logging in, but email verification is disabled");
    }

    let email_routes = if let Some(email_settings) = config.email_smtp.clone() {
        let email_client = web::Data::new(email_settings.build());
        Some(email::configure_routes(
            email_client,
            redis_pool,
            config.email_verify.clone(),
        ))
    } else {
        None
    };

    let database_context = web::Data::new(DatabaseContext::new(db_pool.clone()));

    let bearer_header: &'static str =
        Box::leak(Box::new(format!("Bearer {}", config.shared_secret.clone())));
    info!("starting server at 127.0.0.1:8080");
    HttpServer::new(move || {
        let guard = guard::Header("Authorization", bearer_header);
        let mut main_scope = web::scope("")
            .guard(guard)
            .configure(provider_routes.clone());

        if let Some(email_routes) = email_routes.clone() {
            main_scope = main_scope.configure(email_routes);
        }

        App::new()
            .app_data(config.clone())
            .app_data(database_context.clone())
            .wrap(TracingLogger::default())
            .service(main_scope)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
