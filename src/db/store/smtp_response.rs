use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection};

use crate::db::entries::DbDetails;
use crate::db::store::store::StoreWithDetails;
use crate::db::tables::DbTable;
use crate::helpers::get_timestamp_string;
use crate::proto::appguard::AppGuardSmtpResponse;
use nullnet_liblogging::{location, Error, ErrorHandler, Location};

impl StoreWithDetails for AppGuardSmtpResponse {
    const TABLE: DbTable = DbTable::SmtpResponse;

    fn store_with_details(
        &self,
        conn: &Arc<Mutex<Connection>>,
        details: &DbDetails,
    ) -> Result<(), Error> {
        let table_name = Self::TABLE.to_str();
        conn.lock().handle_err(location!())?.execute(
                &format!("INSERT INTO {table_name} (id, timestamp, fw_res, tcp_id, ip, code, time) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"),
                params![details.id, get_timestamp_string(), details.fw_res, details.tcp_id, &details.ip, &self.code, details.response_time,],
            )
            .handle_err(location!())?;

        Ok(())
    }
}
