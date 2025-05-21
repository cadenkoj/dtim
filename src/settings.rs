use serde::Deserialize;
use std::path::PathBuf;

use crate::node::NodePeer;

#[derive(Debug, Deserialize)]
#[allow(unused)]
pub struct TLSConfig {
    pub key_rotation_days: u64,
    pub ca: Option<PathBuf>,
    pub certs: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Deserialize)]
#[allow(unused)]
pub struct StorageConfig {
    pub encrypted_logs_path: PathBuf,
    #[serde(skip_serializing)]
    pub database_url: String,
}

#[derive(Debug, Deserialize)]
#[allow(unused)]
pub struct NetworkConfig {
    pub gossip_interval_seconds: u64,
    pub peers_per_round: u32,
    pub init_peers: Vec<NodePeer>,
    pub registry_url: String,
}

#[derive(Debug, Deserialize)]
#[allow(unused)]
pub struct PrivacyConfig {
    pub level: String,
    pub allow_custom_fields: bool,
}

#[derive(Debug, Deserialize)]
#[allow(unused)]
pub struct WatchersConfig {
    pub ufw_log_path: PathBuf,
    pub fail2ban_log_path: PathBuf,
    pub suricata_log_path: PathBuf,
    pub zeek_log_dir: PathBuf,
    pub clamav_scan_dir: PathBuf,
    pub nginx_access_log: PathBuf,
    pub nginx_error_log: PathBuf,
    pub apache_access_log: PathBuf,
    pub apache_error_log: PathBuf,
    #[serde(skip_serializing)]
    pub virustotal_api_key: String,
}

#[derive(Debug, Deserialize)]
#[allow(unused)]
pub(crate) struct Settings {
    pub address: String,
    pub port: u16,
    pub log_level: String,
    pub tls: TLSConfig,
    pub storage: StorageConfig,
    pub network: NetworkConfig,
    pub privacy: PrivacyConfig,
    pub watchers: WatchersConfig,
}

#[derive(Debug, Deserialize)]
#[allow(unused)]
struct Root {
    pub default: Settings,
}

impl Settings {
    pub(crate) fn new() -> Result<Settings, config::ConfigError> {
        let config = config::Config::builder()
            .add_source(config::File::with_name("config/mesh"))
            .add_source(config::Environment::with_prefix("DTIM"))
            .build()?;

        let root = config.try_deserialize::<Root>()?;
        Ok(root.default)
    }
}
