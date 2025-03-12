#[derive(Copy, Clone)]
pub enum DbTable {
    TcpConnection,
    HttpRequest,
    HttpResponse,
    IpInfo,
    SmtpRequest,
    SmtpResponse,
}

impl DbTable {
    pub fn to_str(self) -> &'static str {
        match self {
            DbTable::TcpConnection => "tcp_connections",
            DbTable::HttpRequest => "http_requests",
            DbTable::HttpResponse => "http_responses",
            DbTable::IpInfo => "ip_info",
            DbTable::SmtpRequest => "smtp_requests",
            DbTable::SmtpResponse => "smtp_responses",
        }
    }
}
