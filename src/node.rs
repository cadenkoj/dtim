use crate::{
    config::PrivacyConfig,
    logging::EncryptedLogger,
    models::{PrivacyLevel, ThreatIndicator, TlpLevel},
    uuid::Uuid,
};
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, io};

pub struct Node {
    id: Uuid,
    indicators: HashMap<Uuid, ThreatIndicator>,
    peers: Vec<String>,
    logger: EncryptedLogger,
    privacy_level: PrivacyLevel,
    allow_custom_fields: bool,
    keypair: (SigningKey, VerifyingKey),
}

impl Node {
    pub fn new(
        logger: EncryptedLogger,
        privacy: PrivacyConfig,
        keypair: (SigningKey, VerifyingKey),
    ) -> Self {
        Node {
            id: Uuid::new_v7(),
            indicators: HashMap::new(),
            peers: Vec::new(),
            logger,
            privacy_level: match privacy.level.as_str() {
                "strict" => PrivacyLevel::Strict,
                "open" => PrivacyLevel::Open,
                _ => PrivacyLevel::Moderate,
            },
            allow_custom_fields: privacy.allow_custom_fields,
            keypair,
        }
    }

    pub fn get_id(&self) -> String {
        let pubkey_bytes = self.keypair.1.to_bytes();
        let hash = Sha256::digest(&pubkey_bytes);
        hex::encode(&hash)
    }

    pub fn bootstrap_peers(&mut self, peers: Vec<String>) {
        for peer in peers {
            self.peers.push(peer.clone());
            let _ = self
                .logger
                .write_log(log::Level::Info, &format!("Bootstrapping peer: {}", peer));
        }
    }

    pub fn add_indicator(&mut self, indicator: ThreatIndicator) -> Uuid {
        let id = indicator.get_id();
        self.indicators.insert(id, indicator.clone());
        let _ = self.logger.write_log(
            log::Level::Info,
            &format!("Adding indicator: {:?}", indicator),
        );
        id
    }

    pub fn add_or_increment_indicator(&mut self, new_indicator: ThreatIndicator) -> Uuid {
        let id = new_indicator.get_id();
        if let Some(existing) = self.indicators.get_mut(&id) {
            existing.sightings += 1;
            existing.updated_at = Utc::now();
            let _ = self.logger.write_log(
                log::Level::Info,
                &format!("Incrementing indicator: {:?}", existing),
            );
        } else {
            self.add_indicator(new_indicator);
        }
        id
    }

    pub fn get_level(&self) -> PrivacyLevel {
        self.privacy_level
    }

    pub fn get_indicator_by_id(&self, id: &Uuid) -> Option<&ThreatIndicator> {
        self.indicators.get(id)
    }

    pub fn list_indicators_by_tlp(&self, tlp: TlpLevel) -> Vec<ThreatIndicator> {
        self.indicators
            .values()
            .filter(|i| i.tlp == tlp)
            .cloned()
            .collect()
    }

    pub fn list_objects_by_tlp(&self, tlp: TlpLevel) -> Vec<serde_json::Value> {
        let indicators: Vec<_> = self
            .indicators
            .values()
            .filter(|i| i.tlp == tlp)
            .cloned()
            .collect();

        let mut stix_indicators: Vec<serde_json::Value> = indicators
            .iter()
            .map(|i| i.to_stix(self.privacy_level, self.allow_custom_fields))
            .filter_map(|i| i)
            .collect();

        let stix_mds: Vec<serde_json::Value> = self
            .indicators
            .values()
            .flat_map(|i| i.marking_definitions.iter().map(|md| md.to_stix()))
            .collect();

        stix_indicators.extend(stix_mds);
        stix_indicators.sort_by(|a, b| a["id"].as_str().unwrap().cmp(b["id"].as_str().unwrap()));
        stix_indicators
    }

    pub fn get_peers(&self) -> &[String] {
        &self.peers
    }

    pub fn read_logs(&self, date: &str) -> io::Result<Vec<String>> {
        self.logger.read_logs(date)
    }
}
