use anyhow::Result;
use diesel::{
    pg::PgConnection,
    r2d2::{ConnectionManager, Pool},
};

pub fn get_connection_pool(conn_str: &str) -> Result<Pool<ConnectionManager<PgConnection>>> {
    let manager = ConnectionManager::<PgConnection>::new(conn_str);
    let pool = Pool::builder().build(manager)?;
    Ok(pool)
}
