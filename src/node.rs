use crate::{
    crypto::MeshIdentity,
    logging::EncryptedLogger,
    models::{PrivacyLevel, ThreatIndicator, TlpLevel},
    settings::PrivacyConfig,
    uuid::Uuid,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, io};

#[derive(Clone, Debug)]
pub struct Node {
    identity: MeshIdentity,
    indicators: HashMap<Uuid, ThreatIndicator>,
    peers: HashMap<String, NodePeer>,
    logger: EncryptedLogger,
    privacy_level: PrivacyLevel,
    allow_custom_fields: bool,
}

impl Node {
    pub fn new(identity: MeshIdentity, logger: EncryptedLogger, privacy: PrivacyConfig) -> Self {
        Node {
            identity,
            indicators: HashMap::new(),
            peers: HashMap::new(),
            logger,
            privacy_level: match privacy.level.as_str() {
                "strict" => PrivacyLevel::Strict,
                "open" => PrivacyLevel::Open,
                _ => PrivacyLevel::Moderate,
            },
            allow_custom_fields: privacy.allow_custom_fields,
        }
    }

    pub fn identity(&self) -> &MeshIdentity {
        &self.identity
    }

    pub fn get_id(&self) -> String {
        MeshIdentity::derive_hex_id(&self.identity.verifying_key().to_bytes())
    }

    pub fn bootstrap_peers(&mut self, peers: Vec<NodePeer>) {
        for peer in peers {
            self.peers.insert(peer.get_id().to_string(), peer.clone());
            let _ = self.logger.write_log(
                log::Level::Info,
                &format!("Bootstrapping peer: {}", peer.get_endpoint()),
            );
        }
    }

    pub fn add_peer(&mut self, peer: &NodePeer) {
        self.peers.insert(peer.get_id().to_string(), peer.clone());
        let _ = self.logger.write_log(
            log::Level::Info,
            &format!("Adding peer: {}", peer.get_endpoint()),
        );
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
        let indicators: Vec<_> = self.list_indicators_by_tlp(tlp);

        let mut stix_indicators: Vec<serde_json::Value> = indicators
            .iter()
            .filter_map(|i| i.to_stix(self.privacy_level, self.allow_custom_fields))
            .collect();

        let stix_mds: Vec<serde_json::Value> = indicators
            .iter()
            .flat_map(|i| i.marking_definitions.iter().map(|md| md.to_stix()))
            .collect();

        stix_indicators.extend(stix_mds);
        stix_indicators.sort_by(|a, b| a["id"].as_str().unwrap().cmp(b["id"].as_str().unwrap()));
        stix_indicators
    }

    pub fn get_peers(&self) -> &HashMap<String, NodePeer> {
        &self.peers
    }

    pub fn read_logs(&self, date: &str) -> io::Result<Vec<String>> {
        self.logger.read_logs(date)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodePeer {
    pub id: String,
    pub endpoint: String,
    pub public_key: String,
    pub signature: Option<String>,
}

impl NodePeer {
    pub fn get_id(&self) -> &str {
        &self.id
    }

    pub fn get_endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn set_signature(&mut self, signature: String) {
        self.signature = Some(signature);
    }
}

impl PartialEq for NodePeer {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
