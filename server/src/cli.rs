use clap::Parser;

#[derive(Parser, Debug)]
pub struct App {
    #[clap(long, env)]
    pub database_url: String,
    #[clap(long, env)]
    pub config_path: String,
    #[clap(long, env)]
    pub redis_url: String,
}
