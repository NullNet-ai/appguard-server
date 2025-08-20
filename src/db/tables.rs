#[derive(Copy, Clone)]
pub enum DbTable {
    TcpConnection,
    HttpRequest,
    HttpResponse,
    IpInfo,
    SmtpRequest,
    SmtpResponse,
    // Blacklist,
    Firewall,
    Config,
    Alias,
    IpAlias,
}

impl DbTable {
    pub fn to_str(self) -> &'static str {
        match self {
            DbTable::TcpConnection => "tcp_connections",
            DbTable::HttpRequest => "http_requests",
            DbTable::HttpResponse => "http_responses",
            DbTable::IpInfo => "ip_infos",
            DbTable::SmtpRequest => "smtp_requests",
            DbTable::SmtpResponse => "smtp_responses",
            // DbTable::Blacklist => "ip_blacklists",
            DbTable::Firewall => "app_firewalls",
            DbTable::Config => "appguard_configs",
            DbTable::Alias => "aliases",
            DbTable::IpAlias => "ip_aliases",
        }
    }
}
