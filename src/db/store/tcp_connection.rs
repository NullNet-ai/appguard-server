use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection};

use crate::db::store::store::StoreWithId;
use crate::db::tables::DbTable;
use crate::error::Location;
use crate::error::{Error, ErrorHandler};
use crate::helpers::get_timestamp_string;
use crate::location;
use crate::proto::appguard::AppGuardTcpConnection;

impl StoreWithId for AppGuardTcpConnection {
    const TABLE: DbTable = DbTable::TcpConnection;

    fn store_with_id(&self, conn: &Arc<Mutex<Connection>>, id: u64) -> Result<(), Error> {
        let table_name = Self::TABLE.to_str();
        conn.lock().handle_err(location!())?
            .execute(
                &format!("INSERT INTO {table_name} (id, timestamp, source, sport, dest, dport, proto) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"),
                params![
                    id,
                    get_timestamp_string(),
                    &self.source_ip,
                    &self.source_port,
                    &self.destination_ip,
                    &self.destination_port,
                    &self.protocol,
                ],
            ).handle_err(location!())?;

        Ok(())
    }
}
