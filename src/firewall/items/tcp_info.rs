use rpn_predicate_interpreter::PredicateEvaluator;

use crate::firewall::rules::{FirewallRuleField, FirewallRuleWithDirection};
use crate::proto::appguard::{AppGuardIpInfo, AppGuardTcpConnection, AppGuardTcpInfo};

impl<'a> PredicateEvaluator for &'a AppGuardTcpInfo {
    type Predicate = FirewallRuleWithDirection<'a>;
    type Reason = String;

    fn evaluate_predicate(&self, predicate: &Self::Predicate) -> bool {
        match &predicate.rule.field {
            FirewallRuleField::TcpConnection(_) => self
                .connection
                .as_ref()
                .unwrap_or(&AppGuardTcpConnection::default())
                .evaluate_predicate(predicate),
            FirewallRuleField::IpInfo(_) => self
                .ip_info
                .as_ref()
                .unwrap_or(&AppGuardIpInfo::default())
                .evaluate_predicate(predicate),
            _ => false,
        }
    }

    fn get_reason(&self, predicate: &Self::Predicate) -> Self::Reason {
        serde_json::to_string(predicate.rule).unwrap_or_default()
    }

    fn is_blacklisted(&self) -> bool {
        self.ip_info
            .as_ref()
            .unwrap_or(&AppGuardIpInfo::default())
            .is_blacklisted()
    }

    fn get_remote_ip(&self) -> String {
        self.connection
            .as_ref()
            .unwrap_or(&AppGuardTcpConnection::default())
            .get_remote_ip()
    }
}
