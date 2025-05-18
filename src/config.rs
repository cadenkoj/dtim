use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct SecurityConfig {
    pub key_rotation_days: u64,
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct StorageConfig {
    pub encrypted_logs_path: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct NetworkConfig {
    pub gossip_interval_seconds: u64,
    pub peers_per_round: u32,
    pub default_peers: Vec<String>,
    pub registry_url: String,
}

#[derive(Debug, Deserialize)]
pub struct PrivacyConfig {
    pub level: String,
    pub allow_custom_fields: bool,
}

#[derive(Debug, Deserialize)]
pub struct WatchersConfig {
    pub ufw_log_path: PathBuf,
    pub fail2ban_log_path: PathBuf,
    pub suricata_log_path: PathBuf,
    pub zeek_log_dir: PathBuf,
    pub clamav_scan_dir: PathBuf,
    pub virustotal_api_key: String,
    pub nginx_access_log: PathBuf,
    pub nginx_error_log: PathBuf,
    pub apache_access_log: PathBuf,
    pub apache_error_log: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub security: SecurityConfig,
    pub storage: StorageConfig,
    pub network: NetworkConfig,
    pub privacy: PrivacyConfig,
    pub watchers: WatchersConfig,
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
