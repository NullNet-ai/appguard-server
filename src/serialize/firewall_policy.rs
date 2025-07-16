use serde::{Serialize, Serializer};

use crate::proto::appguard_commands::FirewallPolicy;

impl Serialize for FirewallPolicy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            FirewallPolicy::Unknown => serializer.serialize_str("unknown"),
            FirewallPolicy::Allow => serializer.serialize_str("allow"),
            FirewallPolicy::Deny => serializer.serialize_str("deny"),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_firewall_policy() {
        let policy = FirewallPolicy::Allow;
        let serialized = serde_json::to_string(&policy).unwrap();
        assert_eq!(serialized, "\"allow\"");
        let policy = FirewallPolicy::Deny;
        let serialized = serde_json::to_string(&policy).unwrap();
        assert_eq!(serialized, "\"deny\"");
        let policy = FirewallPolicy::Unknown;
        let serialized = serde_json::to_string(&policy).unwrap();
        assert_eq!(serialized, "\"unknown\"");
    }
}
