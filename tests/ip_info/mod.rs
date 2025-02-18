use chrono::{DateTime, Utc};
use rusqlite::Connection;

use appguard_server::db::tables::DbTable;
use appguard_server::proto::appguard::AppGuardIpInfo;

#[allow(dead_code)]
pub struct StoredIpInfo {
    pub id: u32,
    _timestamp: DateTime<Utc>,
    pub ip_info: AppGuardIpInfo,
}

#[allow(dead_code)]
pub fn sample_ip_info() -> AppGuardIpInfo {
    AppGuardIpInfo {
        ip: "::1".to_owned(),
        ..Default::default()
    }
}

#[allow(dead_code)]
pub fn sample_ip_info_2() -> AppGuardIpInfo {
    AppGuardIpInfo {
        ip: "8.8.8.8".to_owned(),
        country: Some("US".to_owned()),
        asn: Some("AS15169".to_owned()),
        org: Some("Google LLC".to_owned()),
        city: Some("Mountain View".to_owned()),
        region: Some("California".to_owned()),
        continent_code: Some("NA".to_owned()),
        postal: Some("99999".to_owned()),
        timezone: Some("LosTime".to_owned()),
        blacklist: 2,
    }
}

#[allow(dead_code)]
pub fn retrieve_stored_ipinfos(conn: &Connection) -> Vec<StoredIpInfo> {
    let table_name = DbTable::IpInfo.to_str();
    let mut stmt = conn
        .prepare(&format!("SELECT * FROM {table_name}"))
        .unwrap();
    let query_result = stmt
        .query_map([], |row| {
            let timestamp_string: String = row.get(1)?;
            let ip_info = AppGuardIpInfo {
                ip: row.get(2)?,
                country: row.get(3)?,
                asn: row.get(4)?,
                org: row.get(5)?,
                continent_code: row.get(6)?,
                city: row.get(7)?,
                region: row.get(8)?,
                postal: row.get(9)?,
                timezone: row.get(10)?,
                blacklist: row.get(11)?,
                ..Default::default()
            };
            Ok(StoredIpInfo {
                id: row.get(0)?,
                _timestamp: DateTime::from(
                    DateTime::parse_from_rfc3339(&timestamp_string).unwrap(),
                ),
                ip_info,
            })
        })
        .unwrap();

    let mut ipinfos = Vec::new();
    for row in query_result {
        ipinfos.push(row.unwrap());
    }
    ipinfos
}
