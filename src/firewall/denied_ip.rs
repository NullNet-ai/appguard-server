pub(crate) struct DeniedIp {
    pub(crate) ip: String,
    pub(crate) deny_reasons: Vec<String>,
}
