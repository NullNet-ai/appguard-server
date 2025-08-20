use std::net::IpAddr;

pub(crate) struct DeniedIp {
    pub(crate) ip: IpAddr,
    pub(crate) _deny_reasons: Vec<String>,
}
