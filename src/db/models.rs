use crate::db::schema::encrypted_indicators;
use diesel::prelude::*;
use diesel::Selectable;
use serde::{Deserialize, Serialize};

#[derive(Queryable, Insertable, Selectable, Serialize, Deserialize, Debug)]
#[diesel(table_name = encrypted_indicators)]
pub struct EncryptedIndicator {
    pub id: String,
    pub data: Vec<u8>,
    pub tlp_level: String,
}
