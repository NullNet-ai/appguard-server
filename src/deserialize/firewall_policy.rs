use serde::{Deserialize, Deserializer};

use crate::proto::appguard::FirewallPolicy;

impl<'de> Deserialize<'de> for FirewallPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;

        match value.as_str() {
            "unknown" => Ok(FirewallPolicy::Unknown),
            "allow" => Ok(FirewallPolicy::Allow),
            "deny" => Ok(FirewallPolicy::Deny),
            _ => Err(serde::de::Error::custom("Invalid FirewallPolicy type")),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_firewall_policy() {
        assert_eq!(
            serde_json::from_str::<FirewallPolicy>(r#""unknown""#).unwrap(),
            FirewallPolicy::Unknown
        );
        assert_eq!(
            serde_json::from_str::<FirewallPolicy>(r#""allow""#).unwrap(),
            FirewallPolicy::Allow
        );
        assert_eq!(
            serde_json::from_str::<FirewallPolicy>(r#""deny""#).unwrap(),
            FirewallPolicy::Deny
        );
        assert!(serde_json::from_str::<FirewallPolicy>(r#""invalid""#).is_err());
    }
}
