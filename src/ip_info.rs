use crate::constants::IP_INFO_API_KEY;
use crate::db::datastore_wrapper::DatastoreWrapper;
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
        token: String,
    ) -> Result<AppGuardIpInfo, Error> {
        let ip_info = ip_info_handler.lookup(ip).await?;
        Self::from_ip_info(ip_info, ip, ds, token).await
    }

    /// This function is used to convert an `IpInfo` struct into an `AppGuardIpInfo` struct.
    async fn from_ip_info(
        info: IpInfo,
        ip: &str,
        ds: &DatastoreWrapper,
        token: String,
    ) -> Result<Self, Error> {
        let blacklist = ds.clone().is_ip_blacklisted(ip, token.as_str()).await?;

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
            blacklist,
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
        get_env(IP_INFO_API_KEY, "IP info API key"),
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
