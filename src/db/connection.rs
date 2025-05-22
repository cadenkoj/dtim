use diesel::{
    pg::PgConnection,
    r2d2::{ConnectionManager, Pool},
};
use std::error::Error;

pub fn get_connection_pool(
    conn_str: &str,
) -> Result<Pool<ConnectionManager<PgConnection>>, Box<dyn Error + Send + Sync>> {
    let manager = ConnectionManager::<PgConnection>::new(conn_str);
    let pool = Pool::builder().build(manager)?;
    Ok(pool)
}
