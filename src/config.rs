use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct SecurityConfig {
    pub key_rotation_days: u64,
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub security: SecurityConfig,
}

impl Config {
    pub fn load() -> Result<Self, config::ConfigError> {
        let config = config::Config::builder()
            .add_source(config::File::with_name("config/default"))
            .add_source(config::Environment::with_prefix("DTIM"))
            .build()?;

        config.try_deserialize()
    }
}
