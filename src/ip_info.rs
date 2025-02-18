use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OptionalExtension};

use crate::constants::API_KEY;
use crate::helpers::get_env;
use crate::proto::appguard::AppGuardIpInfo;
use nullnet_liberror::{location, Error, ErrorHandler, Location};
use nullnet_libipinfo::{ApiFields, IpInfo, IpInfoHandler, IpInfoProvider};

impl AppGuardIpInfo {
    /// This function is used to look up the information about an IP address.
    /// It returns an `AppGuardIpInfo` struct if the lookup is successful, or an error message if it fails.
    pub async fn lookup(
        ip: &str,
        ip_info_handler: &IpInfoHandler,
        blacklist_conn: &Arc<Mutex<Connection>>,
    ) -> Result<AppGuardIpInfo, Error> {
        let ip_info = ip_info_handler.lookup(ip).await?;
        Self::from_ip_info(ip_info, ip, blacklist_conn)
    }

    /// This function is used to convert an `IpInfo` struct into an `AppGuardIpInfo` struct.
    fn from_ip_info(
        info: IpInfo,
        ip: &str,
        blacklist_conn: &Arc<Mutex<Connection>>,
    ) -> Result<Self, Error> {
        let blacklist_count = blacklist_conn
            .lock()
            .handle_err(location!())?
            .query_row("SELECT count FROM blacklist WHERE ip = ?1;", [ip], |row| {
                row.get(0)
            })
            .optional()
            .handle_err(location!())?
            .unwrap_or_default();

        Ok(Self {
            ip: ip.to_string(),
            country: info.country,
            asn: info.asn,
            org: info.org,
            continent_code: info.continent_code,
            city: info.city,
            region: info.region,
            postal: info.postal,
            timezone: info.timezone,
            blacklist: blacklist_count,
        })
    }
}

pub fn ip_info_handler() -> IpInfoHandler {
    IpInfoHandler::new(vec![IpInfoProvider::new_api_provider(
        "https://ipapi.co/{ip}/json/?key={api_key}",
        get_env(API_KEY, "IP info API key"),
        ApiFields {
            country: Some("/country"),
            asn: Some("/asn"),
            org: Some("/org"),
            continent_code: Some("/continent_code"),
            city: Some("/city"),
            region: Some("/region"),
            postal: Some("/postal"),
            timezone: Some("/timezone"),
        },
    )])
    .unwrap()
}
