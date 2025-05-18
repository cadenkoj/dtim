use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
}

impl ThreatIndicator {
    pub fn new(
        indicator_type: IndicatorType,
        value: String,
        confidence: u8,
        sightings: u32,
        tags: Vec<String>,
    ) -> Self {
        ThreatIndicator {
            id: Uuid::now_v7(),
            indicator_type,
            value,
            confidence,
            sightings,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            tags,
        }
    }

    pub fn get_id(&self) -> Uuid {
        self.id
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum IndicatorType {
    Ipv4Address,
    Ipv6Address,
    DomainName,
    Url,
    File,
    EmailAddress,
    Other(String),
}
