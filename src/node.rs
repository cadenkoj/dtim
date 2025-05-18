use crate::{
    config::PrivacyConfig,
    logging::EncryptedLogger,
    models::{PrivacyLevel, ThreatIndicator},
};
use std::{collections::HashMap, io};
use uuid::Uuid;

pub struct Node {
    indicators: HashMap<Uuid, ThreatIndicator>,
    peers: Vec<String>,
    logger: EncryptedLogger,
    level: PrivacyLevel,
    allow_custom_fields: bool,
}

impl Node {
    pub fn new(logger: EncryptedLogger, privacy: PrivacyConfig) -> Self {
        Node {
            indicators: HashMap::new(),
            peers: Vec::new(),
            logger,
            level: match privacy.level.as_str() {
                "strict" => PrivacyLevel::Strict,
                "open" => PrivacyLevel::Open,
                _ => PrivacyLevel::Moderate,
            },
            allow_custom_fields: privacy.allow_custom_fields,
        }
    }

    pub fn bootstrap_peers(&mut self, peers: Vec<String>) {
        for peer in peers {
            self.peers.push(peer.clone());
            let _ = self
                .logger
                .log(log::Level::Info, &format!("Bootstrapping peer: {}", peer));
        }
    }

    pub fn add_indicator(&mut self, indicator: ThreatIndicator) -> Uuid {
        let id = indicator.get_id();
        self.indicators.insert(id, indicator.clone());
        let _ = self.logger.log(
            log::Level::Info,
            &format!("Adding indicator: {:?}", indicator),
        );
        id
    }

    pub fn get_level(&self) -> PrivacyLevel {
        self.level
    }

    pub fn get_allow_custom_fields(&self) -> bool {
        self.allow_custom_fields
    }

    pub fn get_indicator(&self, id: &Uuid) -> Option<&ThreatIndicator> {
        self.indicators.get(id)
    }

    pub fn list_indicators(&self) -> Vec<ThreatIndicator> {
        self.indicators.values().cloned().collect()
    }

    pub fn get_peers(&self) -> &[String] {
        &self.peers
    }

    pub fn read_logs(&self, date: &str) -> io::Result<Vec<String>> {
        self.logger.read_logs(date)
    }
}
