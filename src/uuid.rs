use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display, Formatter};
use std::ops::Deref;
use std::str;
use std::str::FromStr;
use std::sync::Mutex;
use uuid::ContextV7;

static TIMESTAMP_CONTEXT: Lazy<Mutex<ContextV7>> = Lazy::new(|| Mutex::new(ContextV7::new()));

#[derive(
    Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, Hash,
)]
pub struct Uuid(pub uuid::Uuid);

impl From<uuid::Uuid> for Uuid {
    fn from(v: uuid::Uuid) -> Self {
        Uuid(v)
    }
}

impl From<Uuid> for uuid::Uuid {
    fn from(s: Uuid) -> Self {
        s.0
    }
}

impl FromStr for Uuid {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl TryFrom<String> for Uuid {
    type Error = ();
    fn try_from(v: String) -> Result<Self, Self::Error> {
        Self::try_from(v.as_str())
    }
}

impl TryFrom<&str> for Uuid {
    type Error = ();
    fn try_from(v: &str) -> Result<Self, Self::Error> {
        match uuid::Uuid::try_parse(v) {
            Ok(v) => Ok(Self(v)),
            Err(_) => Err(()),
        }
    }
}

impl Deref for Uuid {
    type Target = uuid::Uuid;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Uuid {
    /// Generate a new UUID
    pub fn new_v7() -> Self {
        Self::now_v7()
    }
    /// Generate a new V7 UUID
    pub fn now_v7() -> Self {
        let ctx = TIMESTAMP_CONTEXT.lock().unwrap();
        Self(uuid::Uuid::new_v7(uuid::Timestamp::now(&*ctx)))
    }
    /// Generate a new V5 UUID
    pub fn new_v5_from_hash(hash: &[u8]) -> Self {
        Self(uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, hash))
    }
    /// Generate a new V7 UUID
    pub fn new_v7_from_datetime(timestamp: DateTime<Utc>) -> Self {
        let ctx = TIMESTAMP_CONTEXT.lock().unwrap();
        let ts = uuid::Timestamp::from_unix(
            &*ctx,
            timestamp.timestamp() as u64,
            timestamp.timestamp_subsec_nanos(),
        );
        Self(uuid::Uuid::new_v7(ts))
    }
    /// Convert the Uuid to a raw String
    pub fn to_raw(self) -> String {
        self.0.to_string()
    }
}

impl Display for Uuid {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
