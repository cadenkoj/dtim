use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::IpAddr,
    sync::Arc,
};

use crate::{crypto::SymmetricKeyManager, db::models::EncryptedIndicator, uuid::Uuid};
use chrono::{DateTime, Utc};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ThreatIndicator {
    pub id: Uuid,
    pub indicator_type: IndicatorType,
    pub value: String,
    pub confidence: u8,
    pub sightings: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub tags: BTreeSet<String>,
    pub tlp: TlpLevel,
    pub recipients: Option<Vec<String>>, // Only used for TLP:RED
    pub custom_fields: Option<serde_json::Value>,
    pub marking_definitions: Vec<MarkingDefinition>,
}

#[derive(Serialize)]
#[serde(tag = "privacy_level")]
pub enum IndicatorJSONRef<'a> {
    #[serde(rename = "strict")]
    Strict {
        indicator_type: &'a IndicatorType,
        value: &'a str,
    },
    #[serde(rename = "moderate")]
    Moderate {
        indicator_type: &'a IndicatorType,
        value: &'a str,
        confidence: u8,
        created_at: &'a DateTime<Utc>,
        updated_at: &'a DateTime<Utc>,
    },
    #[serde(rename = "open")]
    Open {
        indicator_type: &'a IndicatorType,
        value: &'a str,
        confidence: u8,
        created_at: &'a DateTime<Utc>,
        updated_at: &'a DateTime<Utc>,
        tags: &'a BTreeSet<String>,
        custom_fields: &'a Option<serde_json::Value>,
        tlp: &'a TlpLevel,
    },
}

#[derive(Serialize)]
#[serde(tag = "type")]
pub enum StixIndicatorView<'a> {
    #[serde(rename = "indicator")]
    Strict {
        id: String,
        pattern: String,
        pattern_type: &'static str,
    },
    #[serde(rename = "indicator")]
    Moderate {
        id: String,
        pattern: String,
        pattern_type: &'static str,
        created: &'a DateTime<Utc>,
        modified: &'a DateTime<Utc>,
        confidence: u8,
    },
    #[serde(rename = "indicator")]
    Open {
        id: String,
        pattern: String,
        pattern_type: &'static str,
        created: &'a DateTime<Utc>,
        modified: &'a DateTime<Utc>,
        confidence: u8,
        labels: &'a BTreeSet<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        extensions: Option<&'a serde_json::Value>,
        granular_markings: Vec<GranularMarking>,
    },
}

#[derive(Serialize)]
pub struct GranularMarking {
    marking_ref: String,
    selectors: &'static [&'static str],
}

impl ThreatIndicator {
    pub fn new(
        indicator_type: IndicatorType,
        value: String,
        confidence: u8,
        tags: BTreeSet<String>,
        tlp: TlpLevel,
        custom_fields_map: Option<BTreeSet<serde_json::Value>>,
    ) -> Result<Self, std::io::Error> {
        let id = Self::compute_id(&indicator_type, &value, &tlp, &tags)
            .map_err(|e| std::io::Error::other(format!("Failed to compute ID: {}", e)))?;
        let now = Utc::now();
        let marking_definition = MarkingDefinition::new("tlp".to_string(), tlp.to_string());
        let custom_fields = custom_fields_map
            .as_ref()
            .map(|hm| serde_json::to_value(hm).unwrap_or(serde_json::Value::Null));

        Ok(ThreatIndicator {
            id,
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
        })
    }

    pub fn get_id(&self) -> String {
        self.id.to_string()
    }

    pub fn compute_id(
        indicator_type: &IndicatorType,
        value: &str,
        tlp: &TlpLevel,
        tags: &BTreeSet<String>,
    ) -> Result<Uuid, std::io::Error> {
        let mut hasher = Sha256::new();
        hasher.update(indicator_type.to_string().as_bytes());
        hasher.update(value.as_bytes());
        hasher.update(tlp.to_string().as_bytes());
        for tag in tags {
            hasher.update(tag.as_bytes());
        }
        let hash = hasher.finalize();
        Ok(Uuid::new_v5_from_hash(&hash))
    }

    pub async fn encrypt(
        &self,
        key_mgr: &Arc<Mutex<SymmetricKeyManager>>,
    ) -> Result<EncryptedIndicator, std::io::Error> {
        let serialized = serde_json::to_vec(self)
            .map_err(|e| std::io::Error::other(format!("Serialization failed: {e}")))?;
        let mut key_mgr = key_mgr.lock().await;
        let data = key_mgr
            .encrypt(&serialized)
            .await
            .map_err(|e| std::io::Error::other(format!("Encryption failed: {}", e)))?;

        Ok(EncryptedIndicator {
            id: self.id.to_string(),
            data,
            tlp_level: self.tlp.to_string(),
        })
    }

    pub async fn decrypt(
        data: &[u8],
        key_mgr: &Arc<Mutex<SymmetricKeyManager>>,
    ) -> Result<Self, std::io::Error> {
        let key_mgr = key_mgr.lock().await;
        let decrypted = key_mgr
            .decrypt(data)
            .map_err(|e| std::io::Error::other(format!("Decryption failed: {}", e)))?;

        serde_json::from_slice(&decrypted).map_err(|e| {
            std::io::Error::other(format!("Failed to deserialize ThreatIndicator: {}", e))
        })
    }

    pub async fn decrypt_batch_parallel(
        encrypted: &[Vec<u8>],
        key_mgr: &Arc<Mutex<SymmetricKeyManager>>,
    ) -> Result<Vec<Self>, std::io::Error> {
        let key_mgr = key_mgr.lock().await;
        let decrypted = key_mgr
            .decrypt_batch_par(encrypted)
            .par_iter()
            .map(|entry| {
                serde_json::from_slice(entry.as_ref().unwrap()).map_err(|e| {
                    std::io::Error::other(format!("Failed to deserialize ThreatIndicator: {}", e))
                })
            })
            .collect::<Result<Vec<Self>, std::io::Error>>()?;
        Ok(decrypted)
    }

    #[allow(unused)] // TODO: implement in watchers
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

    pub fn to_view_ref(&self, level: PrivacyLevel) -> IndicatorJSONRef<'_> {
        match level {
            PrivacyLevel::Strict => IndicatorJSONRef::Strict {
                indicator_type: &self.indicator_type,
                value: &self.value,
            },
            PrivacyLevel::Moderate => IndicatorJSONRef::Moderate {
                indicator_type: &self.indicator_type,
                value: &self.value,
                confidence: self.confidence,
                created_at: &self.created_at,
                updated_at: &self.updated_at,
            },
            PrivacyLevel::Open => IndicatorJSONRef::Open {
                indicator_type: &self.indicator_type,
                value: &self.value,
                confidence: self.confidence,
                created_at: &self.created_at,
                updated_at: &self.updated_at,
                tags: &self.tags,
                custom_fields: &self.custom_fields,
                tlp: &self.tlp,
            },
        }
    }

    pub fn to_json_zero_copy(&self, level: PrivacyLevel) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.to_view_ref(level))
    }

    pub fn from_stix(stix: serde_json::Value) -> Result<Self, String> {
        let indicator = serde_json::from_value(stix)
            .map_err(|e| format!("Failed to deserialize ThreatIndicator: {}", e))?;
        Ok(indicator)
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
                            "marking_ref": md.get_stix_id(),
                            "selectors": vec!["pattern"]
                        })
                    })
                    .collect::<Vec<_>>());
                Some(stix_obj)
            }
        }
    }

    pub fn to_stix_view(
        &self,
        privacy_level: PrivacyLevel,
        allow_custom_fields: bool,
    ) -> Option<StixIndicatorView<'_>> {
        if let IndicatorType::Other(_) = self.indicator_type {
            log::warn!(
                "Cannot convert unknown indicator type to STIX: {:?}",
                self.value
            );
            return None;
        }

        let id = format!("indicator--{}", self.id);
        let pattern = self.get_pattern();

        match privacy_level {
            PrivacyLevel::Strict => Some(StixIndicatorView::Strict {
                id,
                pattern,
                pattern_type: "stix",
            }),
            PrivacyLevel::Moderate => Some(StixIndicatorView::Moderate {
                id,
                pattern,
                pattern_type: "stix",
                created: &self.created_at,
                modified: &self.updated_at,
                confidence: self.confidence,
            }),
            PrivacyLevel::Open => Some(StixIndicatorView::Open {
                id,
                pattern,
                pattern_type: "stix",
                created: &self.created_at,
                modified: &self.updated_at,
                confidence: self.confidence,
                labels: &self.tags,
                extensions: if allow_custom_fields {
                    self.custom_fields.as_ref()
                } else {
                    None
                },
                granular_markings: self
                    .marking_definitions
                    .iter()
                    .map(|md| GranularMarking {
                        marking_ref: md.get_stix_id(),
                        selectors: &["pattern"],
                    })
                    .collect(),
            }),
        }
    }

    pub fn to_stix_fast(
        &self,
        privacy_level: PrivacyLevel,
        allow_custom_fields: bool,
    ) -> Option<String> {
        self.to_stix_view(privacy_level, allow_custom_fields)
            .map(|view| serde_json::to_string(&view).unwrap())
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
            id: Uuid::now_v7(),
            created_at: now,
            definition_type: definition_type.clone(),
            definition: json!({
                definition_type: value,
            }),
        }
    }

    pub fn get_stix_id(&self) -> String {
        format!("marking-definition--{}", self.id)
    }

    pub fn to_stix(&self) -> serde_json::Value {
        json!({
            "type": "marking-definition",
            "id": self.get_stix_id(),
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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
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
pub struct FileHashes(pub BTreeMap<HashAlgorithm, String>);

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
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
