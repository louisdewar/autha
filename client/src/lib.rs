use reqwest::Url;

pub mod error;
pub mod flow;
pub mod email;
pub mod request;

pub struct Client {
    autha_endpoint: Url,
    http: reqwest::Client,
    shared_secret: String,
}

impl Client {
    pub fn new(autha_endpoint: Url, shared_secret: String) -> Self {
        assert!(!autha_endpoint.cannot_be_a_base(), "autha endpoint must be a base URL");
        
        Client {
            http: reqwest::Client::new(),
            autha_endpoint,
            shared_secret,
        }
    }
}