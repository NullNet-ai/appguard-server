use crate::firewall::firewall::FirewallResult;
use crate::proto::appguard::FirewallPolicy;

impl ToSql for FirewallResult {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        let policy_str = match self.policy {
            FirewallPolicy::Unknown => "UNKNOWN",
            FirewallPolicy::Allow => "ALLOW",
            FirewallPolicy::Deny => "DENY",
        };
        let reasons_str = serde_json::to_string(&self.reasons).unwrap_or_default();
        let str = format!("{policy_str} {reasons_str}");
        Ok(ToSqlOutput::from(str))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use rusqlite::types::ToSqlOutput::Owned;
    use rusqlite::types::Value::Text;

    use super::*;

    #[test]
    fn test_firewall_result_to_sql() {
        let firewall_result = FirewallResult {
            policy: FirewallPolicy::Unknown,
            reasons: vec!["a".to_string(), "b".to_string()],
        };
        let to_sql_output = firewall_result.to_sql().unwrap();
        assert_eq!(
            to_sql_output,
            Owned(Text("UNKNOWN [\"a\",\"b\"]".to_string()))
        );
    }
}
