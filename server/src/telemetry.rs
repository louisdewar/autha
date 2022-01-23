use std::env;

use opentelemetry::{
    global, runtime::TokioCurrentThread, sdk::propagation::TraceContextPropagator,
};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{filter::LevelFilter, EnvFilter, Layer, Registry};

// TODO: app name and telemetry endpoint configurable from cli app
pub fn init_telemetry() {
    let app_name = "autha";

    global::set_text_map_propagator(TraceContextPropagator::new());

    let jaeger_endpoint =
        env::var("AUTHA_TELEMETRY_ENDPOINT").unwrap_or_else(|_| "localhost:6831".into());

    let tracer = opentelemetry_jaeger::new_pipeline()
        .with_agent_endpoint(jaeger_endpoint)
        .with_service_name(app_name)
        .install_batch(TokioCurrentThread)
        .expect("Failed to install OpenTelemetry tracer.");

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);

    let formatting_layer = tracing_subscriber::fmt::Layer::new()
        .pretty()
        .with_filter(LevelFilter::INFO);

    let subscriber = Registry::default()
        .with(env_filter)
        .with(telemetry)
        .with(formatting_layer);
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to install `tracing` subscriber.")
}
