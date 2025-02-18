use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection};

use crate::db::entries::DbDetails;
use crate::db::store::store::StoreWithDetails;
use crate::db::tables::DbTable;
use crate::helpers::{get_header, get_timestamp_string};
use crate::proto::appguard::AppGuardHttpResponse;
use nullnet_liblogging::{location, Error, ErrorHandler, Location};

impl StoreWithDetails for AppGuardHttpResponse {
    const TABLE: DbTable = DbTable::HttpResponse;

    fn store_with_details(
        &self,
        conn: &Arc<Mutex<Connection>>,
        details: &DbDetails,
    ) -> Result<(), Error> {
        let headers = &self.headers;

        let size = get_header(headers, "Content-Length");

        let headers_json = serde_json::to_string(headers).handle_err(location!())?;

        let table_name = Self::TABLE.to_str();
        conn.lock().handle_err(location!())?.execute(
                &format!("INSERT INTO {table_name} (id, timestamp, fw_res, tcp_id, ip, code, headers, time, size) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"),
                params![
                    details.id,
                    get_timestamp_string(),
                    details.fw_res,
                    details.tcp_id,
                    &details.ip,
                    &self.code,
                    &headers_json,
                    details.response_time,
                    size,
                ],
            )
            .handle_err(location!())?;

        Ok(())
    }
}
