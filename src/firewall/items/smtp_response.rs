use crate::app_context::AppContext;
use crate::firewall::rules::{
    FirewallCompareType, FirewallRule, FirewallRuleDirection, FirewallRuleField,
    FirewallRuleWithDirection,
};
use crate::proto::appguard::{AppGuardSmtpResponse, AppGuardTcpInfo};
use rpn_predicate_interpreter::PredicateEvaluator;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum SmtpResponseField {
    SmtpResponseCode(Vec<u32>),
}

impl SmtpResponseField {
    // pub fn get_field_name(&self) -> &str {
    //     match self {
    //         SmtpResponseField::SmtpResponseCode(_) => "smtp_response_code",
    //     }
    // }

    fn get_compare_fields<'a>(
        &'a self,
        item: &'a AppGuardSmtpResponse,
    ) -> Option<FirewallCompareType<'a>> {
        match self {
            SmtpResponseField::SmtpResponseCode(v) => item
                .code
                .as_ref()
                .map(|code| FirewallCompareType::U32((*code, v))),
        }
    }
}

#[tonic::async_trait]
impl PredicateEvaluator for AppGuardSmtpResponse {
    type Predicate = FirewallRule;
    type Reason = String;
    type Context = AppContext;

    async fn evaluate_predicate(
        &self,
        predicate: &Self::Predicate,
        context: &Self::Context,
    ) -> bool {
        if predicate.direction == Some(FirewallRuleDirection::In) {
            return false;
        }

        if let FirewallRuleField::SmtpResponse(f) = &predicate.field {
            predicate.condition.compare(f.get_compare_fields(self))
        } else {
            self.tcp_info
                .as_ref()
                .unwrap_or(&AppGuardTcpInfo::default())
                .evaluate_predicate(
                    &FirewallRuleWithDirection {
                        rule: predicate,
                        direction: FirewallRuleDirection::Out,
                    },
                    context,
                )
                .await
        }
    }

    fn get_reason(&self, predicate: &Self::Predicate) -> Self::Reason {
        serde_json::to_string(predicate).unwrap_or_default()
    }

    fn get_remote_ip(&self) -> IpAddr {
        self.tcp_info
            .as_ref()
            .unwrap_or(&AppGuardTcpInfo::default())
            .get_remote_ip()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn sample_smtp_response() -> AppGuardSmtpResponse {
        AppGuardSmtpResponse {
            code: Some(205),
            ..Default::default()
        }
    }

    #[test]
    fn test_smtp_response_get_response_code() {
        let smtp_response = sample_smtp_response();
        let smtp_response_field = SmtpResponseField::SmtpResponseCode(vec![505]);
        assert_eq!(
            smtp_response_field.get_compare_fields(&smtp_response),
            Some(FirewallCompareType::U32((205, &vec![505])))
        );
    }
}
