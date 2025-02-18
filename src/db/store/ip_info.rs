use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection};

use crate::db::store::store::StoreUnique;
use crate::db::tables::DbTable;
use crate::helpers::get_timestamp_string;
use crate::proto::appguard::AppGuardIpInfo;
use nullnet_liblogging::{location, Error, ErrorHandler, Location};

impl StoreUnique for AppGuardIpInfo {
    const TABLE: DbTable = DbTable::IpInfo;

    fn store_unique(&self, conn: &Arc<Mutex<Connection>>) -> Result<Option<u64>, Error> {
        let table_name = Self::TABLE.to_str();
        let c = conn.lock().handle_err(location!())?;

        let mut stmt = c
            .prepare(&format!("SELECT COUNT(*) FROM {table_name} WHERE ip = ?1",))
            .handle_err(location!())?;
        let count: u32 = stmt
            .query_row([&self.ip], |row| row.get(0))
            .handle_err(location!())?;

        if count == 0 {
            c
                .execute(
                    &format!("INSERT INTO {table_name} (timestamp, ip, country, asn, org, continent_code, city, region, postal, timezone, blacklist) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"),
                    params![
                    get_timestamp_string(),
                    &self.ip,
                    &self.country,
                    &self.asn,
                    &self.org,
                    &self.continent_code,
                    &self.city,
                    &self.region,
                    &self.postal,
                    &self.timezone,
                    &self.blacklist,
                ],
                )
                .handle_err(location!())?;
            Ok(Some(c.last_insert_rowid().unsigned_abs()))
        } else {
            Ok(None)
        }
    }
}
