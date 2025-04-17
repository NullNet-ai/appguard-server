use rpn_predicate_interpreter::PredicateEvaluator;
use serde::{Deserialize, Serialize};

use crate::firewall::rules::{FirewallCompareType, FirewallRule, FirewallRuleField};
use crate::helpers::get_header;
use crate::proto::appguard::{AppGuardIpInfo, AppGuardSmtpRequest, AppGuardTcpInfo};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[allow(clippy::enum_variant_names)]
#[serde(rename_all = "snake_case")]
pub enum SmtpRequestField {
    SmtpRequestHeader((String, Vec<String>)),
    SmtpRequestBody(Vec<String>),
    SmtpRequestBodyLen(Vec<usize>),
    SmtpRequestUserAgent(Vec<String>),
}

impl SmtpRequestField {
    pub fn get_field_name(&self) -> &str {
        match self {
            SmtpRequestField::SmtpRequestHeader(_) => "smtp_request_header",
            SmtpRequestField::SmtpRequestBody(_) => "smtp_request_body",
            SmtpRequestField::SmtpRequestBodyLen(_) => "smtp_request_body_len",
            SmtpRequestField::SmtpRequestUserAgent(_) => "smtp_request_user_agent",
        }
    }

    fn get_compare_fields<'a>(
        &'a self,
        item: &'a AppGuardSmtpRequest,
    ) -> Option<FirewallCompareType<'a>> {
        match self {
            SmtpRequestField::SmtpRequestHeader((k, v)) => {
                get_header(&item.headers, k).map(|header| FirewallCompareType::String((header, v)))
            }
            SmtpRequestField::SmtpRequestUserAgent(v) => get_header(&item.headers, "User-Agent")
                .map(|user_agent| FirewallCompareType::String((user_agent, v))),
            SmtpRequestField::SmtpRequestBody(v) => item
                .body
                .as_ref()
                .map(|body| FirewallCompareType::String((body, v))),
            SmtpRequestField::SmtpRequestBodyLen(l) => item
                .body
                .as_ref()
                .map(|body| FirewallCompareType::Usize((body.len(), l))),
        }
    }
}

impl PredicateEvaluator for AppGuardSmtpRequest {
    type Predicate = FirewallRule;
    type Reason = String;

    fn evaluate_predicate(&self, predicate: &Self::Predicate) -> bool {
        match &predicate.field {
            FirewallRuleField::SmtpRequest(f) => {
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

    fn is_blacklisted(&self) -> bool {
        self.tcp_info
            .as_ref()
            .unwrap_or(&AppGuardTcpInfo::default())
            .ip_info
            .as_ref()
            .unwrap_or(&AppGuardIpInfo::default())
            .blacklist
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn sample_smtp_request() -> AppGuardSmtpRequest {
        let mut headers = HashMap::new();
        headers.insert("User-Agent".to_string(), "Thunderbird".to_string());
        headers.insert("Host".to_string(), "Best-Mail UA".to_string());

        AppGuardSmtpRequest {
            headers,
            body: Some("Hello, Jupiter!".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn test_smtp_request_get_header_val() {
        let smtp_request = sample_smtp_request();
        let smtp_request_field = SmtpRequestField::SmtpRequestHeader((
            "user-agent".to_string(),
            vec!["Marlon".to_string()],
        ));
        assert_eq!(
            smtp_request_field.get_compare_fields(&smtp_request),
            Some(FirewallCompareType::String((
                &"Thunderbird".to_string(),
                &vec!["Marlon".to_string()]
            )))
        );

        let smtp_request_field = SmtpRequestField::SmtpRequestHeader((
            "host".to_string(),
            vec!["sample_host".to_string()],
        ));
        assert_eq!(
            smtp_request_field.get_compare_fields(&smtp_request),
            Some(FirewallCompareType::String((
                &"Best-Mail UA".to_string(),
                &vec!["sample_host".to_string()]
            )))
        );

        let smtp_request_field = SmtpRequestField::SmtpRequestHeader((
            "not_exists".to_string(),
            vec!["404".to_string()],
        ));
        assert_eq!(smtp_request_field.get_compare_fields(&smtp_request), None);
    }

    #[test]
    fn test_smtp_request_get_body() {
        let smtp_request = sample_smtp_request();
        let smtp_request_field =
            SmtpRequestField::SmtpRequestBody(vec!["Hello".to_string(), "World!".to_string()]);
        assert_eq!(
            smtp_request_field.get_compare_fields(&smtp_request),
            Some(FirewallCompareType::String((
                &"Hello, Jupiter!".to_string(),
                &vec!["Hello".to_string(), "World!".to_string()]
            )))
        );
    }

    #[test]
    fn test_smtp_request_get_body_len() {
        let smtp_request = sample_smtp_request();
        let smtp_request_field = SmtpRequestField::SmtpRequestBodyLen(vec![7, 99]);
        assert_eq!(
            smtp_request_field.get_compare_fields(&smtp_request),
            Some(FirewallCompareType::Usize((15, &vec![7, 99])))
        );
    }

    #[test]
    fn test_smtp_request_get_user_agent() {
        let smtp_request = sample_smtp_request();
        let smtp_request_field =
            SmtpRequestField::SmtpRequestUserAgent(vec!["awesome_user_agent".to_string()]);
        assert_eq!(
            smtp_request_field.get_compare_fields(&smtp_request),
            Some(FirewallCompareType::String((
                &"Thunderbird".to_string(),
                &vec!["awesome_user_agent".to_string()]
            )))
        );
    }
}
