#[derive(Copy, Clone)]
pub enum DbView {
    HttpRequestDataset,
}

impl DbView {
    pub const ALL: [DbView; 1] = [DbView::HttpRequestDataset];

    pub fn to_str(&self) -> &'static str {
        match self {
            DbView::HttpRequestDataset => "http_request_dataset",
        }
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn sql_create(self) -> String {
        let table_name = self.to_str();
        match self {
            DbView::HttpRequestDataset => format!("
            CREATE VIEW IF NOT EXISTS {table_name}(id, timestamp, fw_res, ai_res, source, sport, country, asn, org, blacklist, original_url, user_agent, headers, method, query, cookies)
                AS
                    SELECT H.id, H.timestamp, fw_res, ai_res, source, sport, country, asn, org, blacklist, original_url, user_agent, headers, method, query, cookies
                    FROM tcp_connection T, ip_info I, http_request H, http_request_ai A
                    WHERE I.ip=H.ip AND T.id=H.tcp_id AND A.id=H.id;"),
        }
    }
}
