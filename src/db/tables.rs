#[derive(Copy, Clone)]
pub enum DbTable {
    // main tables
    TcpConnection,
    HttpRequest,
    HttpResponse,
    IpInfo,
    SmtpRequest,
    SmtpResponse,
    // AI tables
    // HttpRequestAi,
}

impl DbTable {
    // pub const ALL: [DbTable; 6] = [
    //     DbTable::TcpConnection,
    //     DbTable::HttpRequest,
    //     DbTable::HttpResponse,
    //     DbTable::IpInfo,
    //     DbTable::SmtpRequest,
    //     DbTable::SmtpResponse,
    //     // DbTable::HttpRequestAi,
    // ];

    pub fn to_str(self) -> &'static str {
        match self {
            DbTable::TcpConnection => "tcp_connections",
            DbTable::HttpRequest => "http_requests",
            DbTable::HttpResponse => "http_responses",
            DbTable::IpInfo => "ip_info",
            DbTable::SmtpRequest => "smtp_requests",
            DbTable::SmtpResponse => "smtp_responses",
            // DbTable::HttpRequestAi => "http_request_ai",
        }
    }

    // todo: create tables datastore side
    // #[allow(clippy::too_many_lines)]
    // pub(crate) fn sql_create(self) -> String {
    //     let table_name = self.to_str();
    //     match self {
    //         DbTable::TcpConnection => format!(
    //             "
    //             CREATE TABLE IF NOT EXISTS {table_name} (
    //                 id INTEGER PRIMARY KEY,
    //                 timestamp TEXT NOT NULL,
    //                 source TEXT,
    //                 sport INTEGER,
    //                 dest TEXT,
    //                 dport INTEGER,
    //                 proto TEXT NOT NULL
    //             );
    //         "
    //         ),
    //         DbTable::HttpRequest => format!(
    //             "
    //             CREATE TABLE IF NOT EXISTS {table_name} (
    //                 id INTEGER PRIMARY KEY,
    //                 timestamp TEXT NOT NULL,
    //                 fw_res TEXT NOT NULL,
    //                 tcp_id INTEGER NOT NULL,
    //                 ip TEXT NOT NULL,
    //                 original_url TEXT NOT NULL,
    //                 user_agent TEXT,
    //                 headers TEXT NOT NULL,
    //                 method TEXT NOT NULL,
    //                 body TEXT,
    //                 query TEXT NOT NULL,
    //                 cookies TEXT
    //             );
    //         "
    //         ),
    //         DbTable::HttpResponse => format!(
    //             "
    //             CREATE TABLE IF NOT EXISTS {table_name} (
    //                 id INTEGER PRIMARY KEY,
    //                 timestamp TEXT NOT NULL,
    //                 fw_res TEXT NOT NULL,
    //                 tcp_id INTEGER NOT NULL,
    //                 ip TEXT NOT NULL,
    //                 code INTEGER NOT NULL,
    //                 headers TEXT NOT NULL,
    //                 time INTEGER,
    //                 size INTEGER
    //             );
    //         "
    //         ),
    //         DbTable::IpInfo => format!(
    //             "
    //             CREATE TABLE IF NOT EXISTS {table_name} (
    //                 id INTEGER PRIMARY KEY,
    //                 timestamp TEXT NOT NULL,
    //                 ip TEXT NOT NULL,
    //                 country TEXT,
    //                 asn TEXT,
    //                 org TEXT,
    //                 continent_code TEXT,
    //                 city TEXT,
    //                 region TEXT,
    //                 postal TEXT,
    //                 timezone TEXT,
    //                 blacklist INTEGER NOT NULL
    //             );
    //         "
    //         ),
    //         DbTable::SmtpRequest => format!(
    //             "
    //             CREATE TABLE IF NOT EXISTS {table_name} (
    //                 id INTEGER PRIMARY KEY,
    //                 timestamp TEXT NOT NULL,
    //                 fw_res TEXT NOT NULL,
    //                 tcp_id INTEGER NOT NULL,
    //                 ip TEXT NOT NULL,
    //                 user_agent TEXT,
    //                 headers TEXT NOT NULL,
    //                 body TEXT
    //             );
    //         "
    //         ),
    //         DbTable::SmtpResponse => format!(
    //             "
    //             CREATE TABLE IF NOT EXISTS {table_name} (
    //                 id INTEGER PRIMARY KEY,
    //                 timestamp TEXT NOT NULL,
    //                 fw_res TEXT NOT NULL,
    //                 tcp_id INTEGER NOT NULL,
    //                 ip TEXT NOT NULL,
    //                 code INTEGER,
    //                 time INTEGER
    //             );
    //         "
    //         ),
    //         // DbTable::HttpRequestAi => format!(
    //         //     "
    //         //     CREATE TABLE IF NOT EXISTS {table_name} (
    //         //         id INTEGER PRIMARY KEY,
    //         //         timestamp TEXT NOT NULL,
    //         //         ai_res TEXT NOT NULL
    //         //     );
    //         // "
    //         // ),
    //     }
    // }
}
