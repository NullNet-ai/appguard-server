use std::sync::{Arc, Mutex};

use rusqlite::Connection;

use crate::db::entries::DbDetails;
use crate::db::tables::DbTable;
use nullnet_liberror::Error;

pub trait StoreUnique {
    const TABLE: DbTable;

    fn store_unique(&self, conn: &Arc<Mutex<Connection>>) -> Result<Option<u64>, Error>;
}

pub trait StoreWithDetails {
    const TABLE: DbTable;

    fn store_with_details(
        &self,
        conn: &Arc<Mutex<Connection>>,
        details: &DbDetails,
    ) -> Result<(), Error>;
}

pub trait StoreWithId {
    const TABLE: DbTable;

    fn store_with_id(&self, conn: &Arc<Mutex<Connection>>, id: u64) -> Result<(), Error>;
}
