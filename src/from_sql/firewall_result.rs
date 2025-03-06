use crate::firewall::firewall::FirewallResult;
use crate::proto::appguard::FirewallPolicy;

impl FromSql for FirewallResult {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value.data_type() {
            Type::Text => {
                let str = value.as_str()?;
                let v: Vec<&str> = str.splitn(2, ' ').collect();

                let policy_str = v.first().unwrap_or(&"");
                let policy = match *policy_str {
                    "ALLOW" => FirewallPolicy::Allow,
                    "DENY" => FirewallPolicy::Deny,
                    _ => FirewallPolicy::Unknown,
                };

                let reasons_str = v.get(1).unwrap_or(&"");
                let reasons: Vec<String> = serde_json::from_str(reasons_str).unwrap_or_default();

                Ok(FirewallResult::new(policy, reasons))
            }
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn test_firewall_result_from_sql() {
        let value = ValueRef::Text("??? [\"a\"]".as_bytes());
        let result: FirewallResult = FromSql::column_result(value).unwrap();
        assert_eq!(
            result,
            FirewallResult::new(FirewallPolicy::Unknown, vec!["a".to_string()])
        );

        let value = ValueRef::Integer(1);
        let result: Result<FirewallResult, _> = FromSql::column_result(value);
        assert!(result.is_err());
    }
}
