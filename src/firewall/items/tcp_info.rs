use crate::app_context::AppContext;
use crate::firewall::rules::{FirewallRuleField, FirewallRuleWithDirection};
use crate::proto::appguard::{AppGuardIpInfo, AppGuardTcpConnection, AppGuardTcpInfo};
use rpn_predicate_interpreter::PredicateEvaluator;
use std::net::IpAddr;

#[tonic::async_trait]
impl<'a> PredicateEvaluator for &'a AppGuardTcpInfo {
    type Predicate = FirewallRuleWithDirection<'a>;
    type Reason = String;
    type Context = AppContext;

    async fn evaluate_predicate(
        &self,
        predicate: &Self::Predicate,
        context: &Self::Context,
    ) -> bool {
        match &predicate.rule.field {
            FirewallRuleField::TcpConnection(_) => {
                self.connection
                    .as_ref()
                    .unwrap_or(&AppGuardTcpConnection::default())
                    .evaluate_predicate(predicate, context)
                    .await
            }
            FirewallRuleField::IpInfo(_) => {
                self.ip_info
                    .as_ref()
                    .unwrap_or(&AppGuardIpInfo::default())
                    .evaluate_predicate(predicate, context)
                    .await
            }
            _ => false,
        }
    }

    fn get_reason(&self, predicate: &Self::Predicate) -> Self::Reason {
        serde_json::to_string(predicate.rule).unwrap_or_default()
    }

    fn get_remote_ip(&self) -> IpAddr {
        self.connection
            .as_ref()
            .unwrap_or(&AppGuardTcpConnection::default())
            .get_remote_ip()
    }
}
