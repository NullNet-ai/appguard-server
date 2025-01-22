use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection};

use crate::db::entries::DbDetails;
use crate::db::store::store::StoreWithDetails;
use crate::db::tables::DbTable;
use crate::error::Location;
use crate::error::{Error, ErrorHandler};
use crate::helpers::{get_header, get_timestamp_string};
use crate::location;
use crate::proto::appguard::AppGuardHttpRequest;

impl StoreWithDetails for AppGuardHttpRequest {
    const TABLE: DbTable = DbTable::HttpRequest;

    fn store_with_details(
        &self,
        conn: &Arc<Mutex<Connection>>,
        details: &DbDetails,
    ) -> Result<(), Error> {
        let headers = &self.headers;
        let query = &self.query;

        let user_agent = get_header(headers, "User-Agent");
        let cookies = get_header(headers, "Cookie");

        let headers_json = serde_json::to_string(headers).handle_err(location!())?;
        let query_json = serde_json::to_string(query).handle_err(location!())?;

        let table_name = Self::TABLE.to_str();
        conn.lock().handle_err(location!())?.execute(
                &format!("INSERT INTO {table_name} (id, timestamp, fw_res, tcp_id, ip, original_url, user_agent, headers, method, body, query, cookies) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"),
                params![
                    details.id,
                    get_timestamp_string(),
                    details.fw_res,
                    details.tcp_id,
                    &details.ip,
                    &self.original_url,
                    &user_agent,
                    &headers_json,
                    &self.method,
                    &self.body,
                    &query_json,
                    &cookies,
                ],
            ).handle_err(location!())?;

        Ok(())
    }
}
