use crate::constants::API_KEY;
use crate::db::store::store::DatastoreWrapper;
use crate::helpers::get_env;
use crate::proto::appguard::AppGuardIpInfo;
use nullnet_liberror::Error;
use nullnet_libipinfo::{ApiFields, IpInfo, IpInfoHandler, IpInfoProvider};

impl AppGuardIpInfo {
    /// This function is used to look up the information about an IP address.
    /// It returns an `AppGuardIpInfo` struct if the lookup is successful, or an error message if it fails.
    pub async fn lookup(
        ip: &str,
        ip_info_handler: &IpInfoHandler,
        ds: &DatastoreWrapper,
    ) -> Result<AppGuardIpInfo, Error> {
        let ip_info = ip_info_handler.lookup(ip).await?;
        Self::from_ip_info(ip_info, ip, ds)
    }

    /// This function is used to convert an `IpInfo` struct into an `AppGuardIpInfo` struct.
    fn from_ip_info(info: IpInfo, ip: &str, _ds: &DatastoreWrapper) -> Result<Self, Error> {
        // todo: get blacklist count from datastore
        // let blacklist_count = blacklist_conn
        //     .lock()
        //     .handle_err(location!())?
        //     .query_row("SELECT count FROM blacklist WHERE ip = ?1;", [ip], |row| {
        //         row.get(0)
        //     })
        //     .optional()
        //     .handle_err(location!())?
        //     .unwrap_or_default();

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
            // todo: get blacklist from datastore
            blacklist: false,
        })
    }
}

pub fn ip_info_handler() -> IpInfoHandler {
    #[cfg(not(debug_assertions))]
    let url = "https://ipapi.co/{ip}/json/?key={api_key}";
    #[cfg(debug_assertions)]
    let url = "https://ipapi.co/{ip}/json";

    IpInfoHandler::new(vec![IpInfoProvider::new_api_provider(
        url,
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
