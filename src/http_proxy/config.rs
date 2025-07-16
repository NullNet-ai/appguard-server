use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct HttpProxyConfig {
    pub(crate) addr: SocketAddr,
}

impl HttpProxyConfig {
    /// Constructs a `HttpProxyConfig` from the environment variables
    /// `HTTP_PROXY_HOST` and `HTTP_PROXY_PORT`.
    ///
    /// Falls back to `Default` if either environment variable is missing or invalid.
    pub fn from_env() -> Self {
        let host = std::env::var("HTTP_PROXY_HOST").ok();
        let port = std::env::var("HTTP_PROXY_PORT")
            .ok()
            .and_then(|p| p.parse::<u16>().ok());

        if let (Some(host), Some(port)) = (host, port) {
            if let Ok(addr) = format!("{host}:{port}").parse::<SocketAddr>() {
                return Self { addr };
            }
        }

        Self::default()
    }
}

impl Default for HttpProxyConfig {
    fn default() -> Self {
        let addr = "127.0.0.1:4444".parse().unwrap();
        Self { addr }
    }
}
