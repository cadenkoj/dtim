use std::{
    collections::{BTreeSet, HashMap},
    fmt, io,
    net::IpAddr,
};

use crate::{crypto::CryptoContext, uuid::Uuid};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::hash::{Hash, Hasher};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ThreatIndicator {
    pub id: Uuid,
    pub indicator_type: IndicatorType,
    pub value: String,
    pub confidence: u8,
    pub sightings: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub tags: Vec<String>,
    pub tlp: TlpLevel,
    pub recipients: Option<Vec<String>>, // Only used for TLP:RED
    pub custom_fields: Option<HashMap<String, serde_json::Value>>,
    pub marking_definitions: Vec<MarkingDefinition>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncryptedThreatIndicator {
    ciphertext: String,
    nonce: String,
    mac: String,
}

impl ThreatIndicator {
    pub fn new(
        indicator_type: IndicatorType,
        value: String,
        confidence: u8,
        tags: Vec<String>,
        tlp: TlpLevel,
        custom_fields: Option<HashMap<String, serde_json::Value>>,
    ) -> Self {
        let now = Utc::now();
        let marking_definition = MarkingDefinition::new("tlp".to_string(), tlp.to_string());

        ThreatIndicator {
            id: Uuid::new_v7_from_datetime(now),
            indicator_type,
            value,
            confidence,
            sightings: 1,
            created_at: now,
            updated_at: now,
            tags,
            tlp,
            recipients: None, // TODO: Handle recipients for TLP:RED
            custom_fields,
            marking_definitions: vec![marking_definition],
        }
    }

    pub fn get_id(&self) -> Uuid {
        self.id
    }

    pub fn encrypt(
        &self,
        crypto_context: &mut CryptoContext,
    ) -> Result<EncryptedThreatIndicator, io::Error> {
        let serialized = serde_json::to_vec(self).expect("Failed to serialize ThreatIndicator");
        let (ciphertext, nonce, mac) = crypto_context.encrypt(&serialized).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("Encryption failed: {}", e))
        })?;

        Ok(EncryptedThreatIndicator {
            ciphertext,
            nonce,
            mac,
        })
    }

    pub fn decrypt(
        encrypted: &EncryptedThreatIndicator,
        crypto_context: &CryptoContext,
    ) -> Result<Self, String> {
        let decrypted = crypto_context
            .decrypt(&encrypted.ciphertext, &encrypted.nonce, &encrypted.mac)
            .map_err(|e| format!("Decryption failed: {}", e))?;

        serde_json::from_slice(&decrypted)
            .map_err(|e| format!("Failed to deserialize ThreatIndicator: {}", e))
    }

    pub fn infer_type(value: &str) -> IndicatorType {
        if let Ok(ip) = value.parse::<IpAddr>() {
            return match ip {
                IpAddr::V4(_) => IndicatorType::Ipv4Address,
                IpAddr::V6(_) => IndicatorType::Ipv6Address,
            };
        }

        let url_re = Regex::new(r"^https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)$").unwrap();
        if url_re.is_match(value) {
            return IndicatorType::Url;
        }

        let domain_re = Regex::new(r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$").unwrap();
        if domain_re.is_match(value) {
            return IndicatorType::DomainName;
        }

        let email_re = Regex::new(r"^\S+@\S+\.\S+$").unwrap();
        if email_re.is_match(value) {
            return IndicatorType::EmailAddress;
        }

        IndicatorType::Other(value.to_string())
    }

    pub fn get_pattern(&self) -> String {
        match &self.indicator_type {
            IndicatorType::File(hashes) => {
                let patterns: Vec<String> = hashes
                    .0
                    .iter()
                    .map(|(alg, val)| format!("file:hashes.'{}' = '{}'", alg, val))
                    .collect();
                format!("[{}]", patterns.join(" OR "))
            }
            _ => format!("[{}:value = '{}']", self.indicator_type, self.value),
        }
    }

    pub fn to_json(&self, level: PrivacyLevel) -> serde_json::Value {
        let mut json = json!({
            "indicator_type": self.indicator_type,
            "value": self.value,
        });

        match level {
            PrivacyLevel::Strict => json,
            PrivacyLevel::Moderate => {
                json["confidence"] = json!(self.confidence);
                json["created_at"] = json!(self.created_at);
                json["updated_at"] = json!(self.updated_at);
                json
            }
            PrivacyLevel::Open => {
                json["confidence"] = json!(self.confidence);
                json["created_at"] = json!(self.created_at);
                json["updated_at"] = json!(self.updated_at);
                json["tags"] = json!(self.tags);
                json["custom_fields"] = json!(self.custom_fields);
                json["tlp"] = json!(self.tlp);
                json
            }
        }
    }

    pub fn to_stix(
        &self,
        privacy_level: PrivacyLevel,
        allow_custom_fields: bool,
    ) -> Option<serde_json::Value> {
        if let IndicatorType::Other(_) = self.indicator_type {
            log::warn!(
                "Cannot convert unknown indicator type to STIX: {:?}",
                self.value
            );
            return None;
        }

        let mut stix_obj = json!({
            "type": "indicator",
            "id": format!("indicator--{}", self.id),
            "pattern": self.get_pattern(),
            "pattern_type": "stix",
        });

        match privacy_level {
            PrivacyLevel::Strict => Some(stix_obj),
            PrivacyLevel::Moderate => {
                stix_obj["created"] = json!(self.created_at);
                stix_obj["modified"] = json!(self.updated_at);
                stix_obj["confidence"] = json!(self.confidence);
                Some(stix_obj)
            }
            PrivacyLevel::Open => {
                stix_obj["created"] = json!(self.created_at);
                stix_obj["modified"] = json!(self.updated_at);
                stix_obj["confidence"] = json!(self.confidence);
                stix_obj["labels"] = json!(self.tags);
                if allow_custom_fields && self.custom_fields.is_some() {
                    stix_obj["extensions"] = json!(self.custom_fields);
                }
                stix_obj["granular_markings"] = json!(self
                    .marking_definitions
                    .iter()
                    .map(|md| {
                        json!({
                            "marking_ref": md.get_marking_ref(),
                            "selectors": vec!["pattern"]
                        })
                    })
                    .collect::<Vec<_>>());
                Some(stix_obj)
            }
        }
    }
}

impl PartialEq for ThreatIndicator {
    fn eq(&self, other: &Self) -> bool {
        self.indicator_type == other.indicator_type
            && self.value == other.value
            && BTreeSet::<_>::from_iter(self.tags.iter())
                == BTreeSet::<_>::from_iter(other.tags.iter())
            && self.tlp == other.tlp
            && self.custom_fields == other.custom_fields
    }
}

impl Eq for ThreatIndicator {}

impl std::hash::Hash for ThreatIndicator {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.indicator_type.hash(state);
        self.value.hash(state);
        let mut sorted_tags: Vec<_> = self.tags.iter().collect();
        sorted_tags.sort();
        for tag in sorted_tags {
            tag.hash(state);
        }
        self.tlp.hash(state);
        if let Some(fields) = &self.custom_fields {
            for (k, v) in fields {
                k.hash(state);
                v.to_string().hash(state);
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MarkingDefinition {
    id: Uuid,
    created_at: DateTime<Utc>,
    definition_type: String,
    definition: serde_json::Value,
}

impl MarkingDefinition {
    pub fn new(definition_type: String, value: String) -> Self {
        let now = Utc::now();

        MarkingDefinition {
            id: Uuid::new_v7_from_datetime(now),
            created_at: now,
            definition_type: definition_type.clone(),
            definition: json!({
                definition_type: value,
            }),
        }
    }

    pub fn get_marking_ref(&self) -> String {
        format!("marking-definition--{}", self.id)
    }

    pub fn to_stix(&self) -> serde_json::Value {
        json!({
            "type": "marking-definition",
            "id": self.get_marking_ref(),
            "created": self.created_at,
            "definition_type": self.definition_type,
            "definition": self.definition,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StixBundle {
    pub id: String,
    pub objects: Vec<serde_json::Value>,
}

impl StixBundle {
    pub fn new(objects: Vec<serde_json::Value>) -> Self {
        let now = Utc::now();

        StixBundle {
            id: format!("bundle--{}", Uuid::new_v7_from_datetime(now)),
            objects,
        }
    }

    pub fn to_stix(&self) -> serde_json::Value {
        json!({
            "type": "bundle",
            "id": self.id,
            "objects": self.objects,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum TlpLevel {
    Red,
    Amber,
    Green,
    White,
}

impl std::fmt::Display for TlpLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlpLevel::Red => write!(f, "red"),
            TlpLevel::Amber => write!(f, "amber"),
            TlpLevel::Green => write!(f, "green"),
            TlpLevel::White => write!(f, "white"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct FileHashes(pub HashMap<HashAlgorithm, String>);

impl Hash for FileHashes {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for (k, v) in &self.0 {
            k.hash(state);
            v.hash(state);
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    MD5,
    SHA1,
    SHA256,
    SHA512,
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashAlgorithm::MD5 => write!(f, "MD5"),
            HashAlgorithm::SHA1 => write!(f, "SHA-1"),
            HashAlgorithm::SHA256 => write!(f, "SHA-256"),
            HashAlgorithm::SHA512 => write!(f, "SHA-512"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Hash)]
pub enum IndicatorType {
    Ipv4Address,
    Ipv6Address,
    DomainName,
    Url,
    File(FileHashes),
    EmailAddress,
    Other(String),
}

impl fmt::Display for IndicatorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IndicatorType::Ipv4Address => write!(f, "ipv4-addr"),
            IndicatorType::Ipv6Address => write!(f, "ipv6-addr"),
            IndicatorType::DomainName => write!(f, "domain-name"),
            IndicatorType::Url => write!(f, "url"),
            IndicatorType::File(_) => write!(f, "file"),
            IndicatorType::EmailAddress => write!(f, "email-addr"),
            IndicatorType::Other(s) => write!(f, "{}", s),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivacyLevel {
    Strict,
    Moderate,
    Open,
}

impl fmt::Display for PrivacyLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrivacyLevel::Strict => write!(f, "strict"),
            PrivacyLevel::Moderate => write!(f, "moderate"),
            PrivacyLevel::Open => write!(f, "open"),
        }
    }
}
