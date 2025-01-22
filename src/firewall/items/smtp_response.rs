use rpn_predicate_interpreter::PredicateEvaluator;
use serde::{Deserialize, Serialize};

use crate::firewall::rules::{FirewallCompareType, FirewallRule, FirewallRuleField};
use crate::proto::appguard::{AppGuardSmtpResponse, AppGuardTcpInfo};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SmtpResponseField {
    ResponseCode(Vec<u32>),
}

impl SmtpResponseField {
    pub fn get_field_name(&self) -> &str {
        match self {
            SmtpResponseField::ResponseCode(_) => "response_code",
        }
    }

    fn get_compare_fields<'a>(
        &'a self,
        item: &'a AppGuardSmtpResponse,
    ) -> Option<FirewallCompareType<'a>> {
        match self {
            SmtpResponseField::ResponseCode(v) => item
                .code
                .as_ref()
                .map(|code| FirewallCompareType::U32((*code, v))),
        }
    }
}

impl PredicateEvaluator for AppGuardSmtpResponse {
    type Predicate = FirewallRule;
    type Reason = String;

    fn evaluate_predicate(&self, predicate: &Self::Predicate) -> bool {
        match &predicate.field {
            FirewallRuleField::SmtpResponse(f) => {
                predicate.condition.compare(f.get_compare_fields(self))
            }
            _ => self
                .tcp_info
                .as_ref()
                .unwrap_or(&AppGuardTcpInfo::default())
                .evaluate_predicate(predicate),
        }
    }

    fn get_reason(&self, predicate: &Self::Predicate) -> Self::Reason {
        predicate.field.get_field_name()
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
        let smtp_response_field = SmtpResponseField::ResponseCode(vec![505]);
        assert_eq!(
            smtp_response_field.get_compare_fields(&smtp_response),
            Some(FirewallCompareType::U32((205, &vec![505])))
        );
    }
}
