use rpn_predicate_interpreter::PredicateEvaluator;

use crate::firewall::rules::{FirewallRule, FirewallRuleField};
use crate::proto::appguard::{AppGuardIpInfo, AppGuardTcpConnection, AppGuardTcpInfo};

impl PredicateEvaluator for AppGuardTcpInfo {
    type Predicate = FirewallRule;
    type Reason = String;

    fn evaluate_predicate(&self, predicate: &Self::Predicate) -> bool {
        match &predicate.field {
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
        predicate.field.get_field_name()
    }
}
