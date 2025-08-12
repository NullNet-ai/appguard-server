use crate::app_context::AppContext;
use crate::firewall::header_val::HeaderVal;
use crate::firewall::rules::{
    FirewallCompareType, FirewallRule, FirewallRuleDirection, FirewallRuleField,
    FirewallRuleWithDirection,
};
use crate::helpers::get_header;
use crate::proto::appguard::{AppGuardSmtpRequest, AppGuardTcpInfo};
use rpn_predicate_interpreter::PredicateEvaluator;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[allow(clippy::enum_variant_names)]
#[serde(rename_all = "snake_case")]
pub enum SmtpRequestField {
    SmtpRequestHeader(HeaderVal),
    SmtpRequestBody(Vec<String>),
    SmtpRequestBodyLen(Vec<usize>),
    SmtpRequestUserAgent(Vec<String>),
}

impl SmtpRequestField {
    // pub fn get_field_name(&self) -> &str {
    //     match self {
    //         SmtpRequestField::SmtpRequestHeader(_) => "smtp_request_header",
    //         SmtpRequestField::SmtpRequestBody(_) => "smtp_request_body",
    //         SmtpRequestField::SmtpRequestBodyLen(_) => "smtp_request_body_len",
    //         SmtpRequestField::SmtpRequestUserAgent(_) => "smtp_request_user_agent",
    //     }
    // }

    fn get_compare_fields<'a>(
        &'a self,
        item: &'a AppGuardSmtpRequest,
    ) -> Option<FirewallCompareType<'a>> {
        match self {
            SmtpRequestField::SmtpRequestHeader(HeaderVal(k, v)) => {
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

#[tonic::async_trait]
impl PredicateEvaluator for AppGuardSmtpRequest {
    type Predicate = FirewallRule;
    type Reason = String;
    type Context = AppContext;

    async fn evaluate_predicate(
        &self,
        predicate: &Self::Predicate,
        context: &Self::Context,
    ) -> bool {
        if predicate.direction == Some(FirewallRuleDirection::Out) {
            return false;
        }

        if let FirewallRuleField::SmtpRequest(f) = &predicate.field {
            predicate.condition.compare(f.get_compare_fields(self))
        } else {
            self.tcp_info
                .as_ref()
                .unwrap_or(&AppGuardTcpInfo::default())
                .evaluate_predicate(
                    &FirewallRuleWithDirection {
                        rule: predicate,
                        direction: FirewallRuleDirection::In,
                    },
                    context,
                )
                .await
        }
    }

    fn get_reason(&self, predicate: &Self::Predicate) -> Self::Reason {
        serde_json::to_string(predicate).unwrap_or_default()
    }

    fn get_remote_ip(&self) -> String {
        self.tcp_info
            .as_ref()
            .unwrap_or(&AppGuardTcpInfo::default())
            .get_remote_ip()
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
        let smtp_request_field = SmtpRequestField::SmtpRequestHeader(HeaderVal(
            "user-agent".to_string(),
            vec!["Marlon".to_string()],
        ));
        assert_eq!(
            smtp_request_field.get_compare_fields(&smtp_request),
            Some(FirewallCompareType::String((
                &"Thunderbird".to_string(),
                Cow::Borrowed(&vec!["Marlon".to_string()])
            )))
        );

        let smtp_request_field = SmtpRequestField::SmtpRequestHeader(HeaderVal(
            "host".to_string(),
            vec!["sample_host".to_string()],
        ));
        assert_eq!(
            smtp_request_field.get_compare_fields(&smtp_request),
            Some(FirewallCompareType::String((
                &"Best-Mail UA".to_string(),
                Cow::Borrowed(&vec!["sample_host".to_string()])
            )))
        );

        let smtp_request_field = SmtpRequestField::SmtpRequestHeader(HeaderVal(
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
                Cow::Borrowed(&vec!["Hello".to_string(), "World!".to_string()])
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
                Cow::Borrowed(&vec!["awesome_user_agent".to_string()])
            )))
        );
    }
}
