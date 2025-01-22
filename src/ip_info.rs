use std::sync::{Arc, Mutex, RwLock};

use maxminddb::MaxMindDBError;
use reqwest::Client;
use rusqlite::{Connection, OptionalExtension};
use serde::Deserialize;

use crate::constants::IP_API_LINK;
use crate::error::{Error, ErrorHandler, Location};
use crate::fetch_data::MmdbReader;
use crate::location;
use crate::proto::appguard::AppGuardIpInfo;

#[derive(Deserialize, Debug, PartialEq, Default)]
struct IpInfo {
    country: Option<String>,
    asn: Option<String>,
    #[serde(alias = "as_name")]
    org: Option<String>,
    // additional fields...
    #[serde(alias = "continent")]
    continent_code: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    postal: Option<String>,
    #[serde(default)]
    timezone: Option<String>,
}

impl IpInfo {
    /// This function is used to convert an `IpInfo` struct into an `AppGuardIpInfo` struct.
    fn into_app_guard_ip_info(
        self,
        ip: &str,
        blacklist_conn: &Arc<Mutex<Connection>>,
    ) -> Result<AppGuardIpInfo, Error> {
        let blacklist_count = blacklist_conn
            .lock()
            .handle_err(location!())?
            .query_row("SELECT count FROM blacklist WHERE ip = ?1;", [ip], |row| {
                row.get(0)
            })
            .optional()
            .handle_err(location!())?
            .unwrap_or_default();

        Ok(AppGuardIpInfo {
            ip: ip.to_string(),
            country: self.country,
            asn: self.asn,
            org: self.org,
            continent_code: self.continent_code,
            city: self.city,
            region: self.region,
            postal: self.postal,
            timezone: self.timezone,
            blacklist: blacklist_count,
        })
    }

    async fn lookup_from_api(client: &Client, api_key: &str, ip: &str) -> Result<IpInfo, Error> {
        client
            .get(format!("{IP_API_LINK}/{ip}/json/{api_key}"))
            .send()
            .await
            .handle_err(location!())?
            .json::<IpInfo>()
            .await
            .handle_err(location!())
    }

    fn lookup_from_mmdb(mmdb_reader: &Arc<RwLock<MmdbReader>>, ip: &str) -> Result<IpInfo, Error> {
        let ip_info_res = mmdb_reader
            .read()
            .handle_err(location!())?
            .lookup::<IpInfo>(ip.parse().handle_err(location!())?);

        if let Err(MaxMindDBError::AddressNotFoundError(_)) = ip_info_res {
            return Ok(IpInfo::default());
        }

        ip_info_res.handle_err(location!())
    }
}

impl AppGuardIpInfo {
    /// This function is used to look up the information about an IP address.
    /// It returns an `AppGuardIpInfo` struct if the lookup is successful, or an error message if it fails.
    pub async fn lookup(
        ip: &str,
        client: &Client,
        api_key: &str,
        mmdb_reader: &Arc<RwLock<MmdbReader>>,
        blacklist_conn: &Arc<Mutex<Connection>>,
    ) -> Result<AppGuardIpInfo, Error> {
        let ip_info = IpInfo::lookup_from_api(client, api_key, ip)
            .await
            .or_else(|_| {
                log::warn!("Failed to look up IP info from API, trying with MMDB...");
                IpInfo::lookup_from_mmdb(mmdb_reader, ip)
            })?;
        ip_info.into_app_guard_ip_info(ip, blacklist_conn)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::constants::{API_KEY, BLACKLIST_PATH};
    use crate::fetch_data::client_builder_with_ua;
    use crate::helpers::get_env;

    use super::*;

    #[tokio::test]
    async fn test_lookup_ip_info_from_api() {
        let client = client_builder_with_ua().build().expect("Test");
        let blacklist_conn = Arc::new(Mutex::new(Connection::open(BLACKLIST_PATH).expect("Test")));

        let api_key = get_env(API_KEY, "key", "IP info API key");
        let ip_info = IpInfo::lookup_from_api(&client, &api_key, "8.8.8.8")
            .await
            .expect("Test");

        assert_eq!(
            ip_info,
            IpInfo {
                country: Some("US".to_string()),
                asn: Some("AS15169".to_string()),
                org: Some("GOOGLE".to_string()),
                continent_code: Some("NA".to_string()),
                city: Some("Mountain View".to_string()),
                region: Some("California".to_string()),
                postal: Some("94043".to_string()),
                timezone: Some("America/Los_Angeles".to_string())
            }
        );

        assert_eq!(
            ip_info
                .into_app_guard_ip_info("8.8.8.8", &blacklist_conn)
                .expect("Test"),
            AppGuardIpInfo {
                ip: "8.8.8.8".to_string(),
                country: Some("US".to_string()),
                asn: Some("AS15169".to_string()),
                org: Some("GOOGLE".to_string()),
                continent_code: Some("NA".to_string()),
                city: Some("Mountain View".to_string()),
                region: Some("California".to_string()),
                postal: Some("94043".to_string()),
                timezone: Some("America/Los_Angeles".to_string()),
                ..Default::default()
            }
        );
    }

    #[test]
    fn test_lookup_ip_info_from_mmdb() {
        let reader = Arc::new(RwLock::new(MmdbReader::Reader(
            maxminddb::Reader::open_readfile("test_material/ip_country_asn_sample.mmdb")
                .expect("Test"),
        )));
        let blacklist_conn = Arc::new(Mutex::new(Connection::open(BLACKLIST_PATH).expect("Test")));

        let ip_info = IpInfo::lookup_from_mmdb(&reader, "20.20.8.57").expect("Test");
        assert_eq!(
            ip_info,
            IpInfo {
                country: Some("ID".to_string()),
                asn: Some("AS8075".to_string()),
                org: Some("Microsoft Corporation".to_string()),
                continent_code: Some("AS".to_string()),
                city: None,
                region: None,
                postal: None,
                timezone: None
            }
        );
        assert_eq!(
            ip_info
                .into_app_guard_ip_info("20.20.8.57", &blacklist_conn)
                .expect("Test"),
            AppGuardIpInfo {
                ip: "20.20.8.57".to_string(),
                country: Some("ID".to_string()),
                asn: Some("AS8075".to_string()),
                org: Some("Microsoft Corporation".to_string()),
                continent_code: Some("AS".to_string()),
                city: None,
                region: None,
                postal: None,
                timezone: None,
                blacklist: 3,
                ..Default::default()
            }
        );

        let ip_info = IpInfo::lookup_from_mmdb(&reader, "10.0.0.1").expect("Test");
        assert_eq!(ip_info, IpInfo::default());
        assert_eq!(
            ip_info
                .into_app_guard_ip_info("10.0.0.1", &blacklist_conn)
                .expect("Test"),
            AppGuardIpInfo {
                ip: "10.0.0.1".to_string(),
                ..Default::default()
            }
        );

        let ip_info =
            IpInfo::lookup_from_mmdb(&Arc::new(RwLock::new(MmdbReader::default())), "20.20.8.57")
                .expect("Test");
        assert_eq!(ip_info, IpInfo::default());
        assert_eq!(
            ip_info
                .into_app_guard_ip_info("20.20.8.57", &blacklist_conn)
                .expect("Test"),
            AppGuardIpInfo {
                ip: "20.20.8.57".to_string(),
                blacklist: 3,
                ..Default::default()
            }
        );
    }

    #[tokio::test]
    async fn test_lookup_ip_info_errors() {
        let client = client_builder_with_ua().build().expect("Test");
        let blacklist_conn = Arc::new(Mutex::new(Connection::open(BLACKLIST_PATH).expect("Test")));

        // invalid IP
        let ip_info = AppGuardIpInfo::lookup(
            "i'm not an IP",
            &client,
            "",
            &Arc::new(RwLock::new(MmdbReader::default())),
            &blacklist_conn,
        )
        .await;
        assert!(ip_info.is_err());

        // invalid API key
        let ip_info = AppGuardIpInfo::lookup(
            "10.0.0.1",
            &client,
            "hello_world",
            &Arc::new(RwLock::new(MmdbReader::default())),
            &blacklist_conn,
        )
        .await
        .expect("Test");
        assert_eq!(
            ip_info,
            AppGuardIpInfo {
                ip: "10.0.0.1".to_string(),
                ..Default::default()
            }
        );
    }
}
