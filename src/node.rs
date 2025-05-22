use crate::{
    crypto::{self, MeshIdentity, SymmetricKeyManager},
    db::{self, models::EncryptedIndicator},
    logging::EncryptedLogger,
    models::{PrivacyLevel, ThreatIndicator, TlpLevel},
    settings::PrivacyConfig,
};
use chrono::Utc;
use diesel::{
    pg::PgConnection,
    query_dsl::methods::{FilterDsl, FindDsl},
    r2d2::Pool,
    upsert::excluded,
    OptionalExtension,
};
use diesel::{r2d2::ConnectionManager, ExpressionMethods};
use diesel::{RunQueryDsl, SelectableHelper};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, io};

#[derive(Clone, Debug)]
pub struct Node {
    identity: MeshIdentity,
    peers: HashMap<String, NodePeer>,
    db_pool: Pool<ConnectionManager<PgConnection>>,
    key_mgr: SymmetricKeyManager,
    logger: EncryptedLogger,
    privacy_level: PrivacyLevel,
    allow_custom_fields: bool,
}

impl Node {
    pub fn new(
        db_pool: Pool<ConnectionManager<PgConnection>>,
        key_mgr: SymmetricKeyManager,
        logger: EncryptedLogger,
        privacy: PrivacyConfig,
    ) -> Result<Self, std::io::Error> {
        let identity = crypto::MeshIdentity::load_or_generate()?;
        Ok(Node {
            identity,
            peers: HashMap::new(),
            db_pool,
            key_mgr,
            logger,
            privacy_level: match privacy.level.as_str() {
                "strict" => PrivacyLevel::Strict,
                "open" => PrivacyLevel::Open,
                _ => PrivacyLevel::Moderate,
            },
            allow_custom_fields: privacy.allow_custom_fields,
        })
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

    pub fn add_indicator(
        &mut self,
        indicator: ThreatIndicator,
    ) -> Result<EncryptedIndicator, Box<dyn std::error::Error + Send + Sync>> {
        use self::db::schema::encrypted_indicators::dsl::*;

        let encrypted_indicator = indicator.encrypt(&mut self.key_mgr)?;

        let mut conn = self.db_pool.get()?;
        let res = diesel::insert_into(encrypted_indicators)
            .values(&encrypted_indicator)
            .on_conflict(id)
            .do_nothing()
            .returning(EncryptedIndicator::as_returning())
            .get_result(&mut conn)?;

        let _ = self.logger.write_log(
            log::Level::Info,
            &format!("Added indicator with id: {}", res.id),
        );
        Ok(res)
    }

    pub fn add_or_increment_indicator(
        &mut self,
        new_indicator: ThreatIndicator,
    ) -> Result<EncryptedIndicator, Box<dyn std::error::Error + Send + Sync>> {
        use self::db::schema::encrypted_indicators::dsl::*;

        let indicator_id = new_indicator.get_id();

        let mut conn = self.db_pool.get()?;
        let existing: Option<EncryptedIndicator> = encrypted_indicators
            .find(&indicator_id)
            .first::<EncryptedIndicator>(&mut conn)
            .optional()?;

        if let Some(encrypted) = existing {
            let mut indicator = ThreatIndicator::decrypt(&encrypted, &self.key_mgr)?;
            indicator.sightings += 1;
            indicator.updated_at = Utc::now();

            let new_encrypted = indicator.encrypt(&mut self.key_mgr)?;
            let res = diesel::update(encrypted_indicators.find(&indicator_id))
                .set((
                    ciphertext.eq(new_encrypted.ciphertext),
                    nonce.eq(new_encrypted.nonce),
                    mac.eq(new_encrypted.mac),
                ))
                .returning(EncryptedIndicator::as_returning())
                .get_result(&mut conn)?;

            let _ = self.logger.write_log(
                log::Level::Info,
                &format!("Incrementing indicator with id: {}", res.id),
            );
            Ok(res)
        } else {
            let encrypted = new_indicator.encrypt(&mut self.key_mgr)?;
            let res = diesel::insert_into(encrypted_indicators)
                .values(&encrypted)
                .on_conflict(id)
                .do_update()
                .set(ciphertext.eq(excluded(ciphertext))) // Update with the new values
                .returning(EncryptedIndicator::as_returning())
                .get_result(&mut conn)?;

            let _ = self
                .logger
                .write_log(log::Level::Info, &format!("Adding indicator: {:?}", res));
            Ok(res)
        }
    }

    pub fn get_level(&self) -> PrivacyLevel {
        self.privacy_level
    }

    pub fn get_indicator_by_id(
        &self,
        indicator_id: &String,
    ) -> Result<ThreatIndicator, Box<dyn std::error::Error + Send + Sync>> {
        use self::db::schema::encrypted_indicators::dsl::*;

        let mut conn = self.db_pool.get()?;
        let indicator = encrypted_indicators
            .find(indicator_id)
            .first::<EncryptedIndicator>(&mut conn)?;

        let indicator = ThreatIndicator::decrypt(&indicator, &self.key_mgr)?;
        Ok(indicator)
    }

    pub fn list_indicators_by_tlp(
        &self,
        tlp: TlpLevel,
    ) -> Result<Vec<ThreatIndicator>, Box<dyn std::error::Error + Send + Sync>> {
        use self::db::schema::encrypted_indicators::dsl::*;

        let mut conn = self.db_pool.get()?;
        let indicators = encrypted_indicators
            .filter(tlp_level.eq(tlp.to_string()))
            .load::<EncryptedIndicator>(&mut conn)?;

        let indicators = indicators
            .iter()
            .map(|i| ThreatIndicator::decrypt(i, &self.key_mgr))
            .collect::<Result<Vec<ThreatIndicator>, std::io::Error>>()?;

        Ok(indicators)
    }

    pub fn list_objects_by_tlp(
        &self,
        tlp: TlpLevel,
    ) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error + Send + Sync>> {
        let indicators = self.list_indicators_by_tlp(tlp)?;

        println!("Indicators: {:?}", indicators);

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
        Ok(stix_indicators)
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
