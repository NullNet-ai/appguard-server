use rpn_predicate_interpreter::PredicateEvaluator;
use serde::{Deserialize, Serialize};

use crate::firewall::rules::{FirewallCompareType, FirewallRule, FirewallRuleField};
use crate::helpers::get_header;
use crate::proto::appguard::{AppGuardHttpResponse, AppGuardTcpInfo};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HttpResponseField {
    ResponseSize(Vec<u64>),
    ResponseCode(Vec<u32>),
    HeaderVal((String, Vec<String>)),
}

impl HttpResponseField {
    pub fn get_field_name(&self) -> &str {
        match self {
            HttpResponseField::ResponseSize(_) => "response_size",
            HttpResponseField::ResponseCode(_) => "response_code",
            HttpResponseField::HeaderVal(_) => "header_val",
        }
    }

    fn get_compare_fields<'a>(
        &'a self,
        item: &'a AppGuardHttpResponse,
    ) -> Option<FirewallCompareType<'a>> {
        match self {
            HttpResponseField::ResponseCode(v) => Some(FirewallCompareType::U32((item.code, v))),
            HttpResponseField::ResponseSize(s) => {
                if let Ok(size) = get_header(&item.headers, "Content-Length")
                    .unwrap_or(&String::new())
                    .parse::<u64>()
                {
                    Some(FirewallCompareType::U64((size, s)))
                } else {
                    None
                }
            }
            HttpResponseField::HeaderVal((k, v)) => {
                get_header(&item.headers, k).map(|header| FirewallCompareType::String((header, v)))
            }
        }
    }
}

impl PredicateEvaluator for AppGuardHttpResponse {
    type Predicate = FirewallRule;
    type Reason = String;

    fn evaluate_predicate(&self, predicate: &Self::Predicate) -> bool {
        match &predicate.field {
            FirewallRuleField::HttpResponse(f) => {
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
    use std::collections::HashMap;

    use super::*;

    fn sample_http_response() -> AppGuardHttpResponse {
        let mut headers = HashMap::new();
        headers.insert("Host".to_string(), "example.com".to_string());
        headers.insert("Content-Length".to_string(), "139".to_string());

        AppGuardHttpResponse {
            headers,
            code: 200,
            ..Default::default()
        }
    }

    #[test]
    fn test_http_response_get_response_size() {
        let http_response = sample_http_response();
        let http_response_field = HttpResponseField::ResponseSize(vec![931]);
        assert_eq!(
            http_response_field.get_compare_fields(&http_response),
            Some(FirewallCompareType::U64((139, &vec![931])))
        );
    }

    #[test]
    fn test_http_response_get_response_code() {
        let http_response = sample_http_response();
        let http_response_field = HttpResponseField::ResponseCode(vec![404]);
        assert_eq!(
            http_response_field.get_compare_fields(&http_response),
            Some(FirewallCompareType::U32((200, &vec![404])))
        );
    }

    #[test]
    fn test_http_response_get_header_val() {
        let http_response = sample_http_response();
        let http_response_field =
            HttpResponseField::HeaderVal(("hoST".to_string(), vec!["ciao".to_string()]));
        assert_eq!(
            http_response_field.get_compare_fields(&http_response),
            Some(FirewallCompareType::String((
                &"example.com".to_string(),
                &vec!["ciao".to_string()]
            )))
        );

        let http_response_field =
            HttpResponseField::HeaderVal(("Content-Length".to_string(), vec!["9999".to_string()]));
        assert_eq!(
            http_response_field.get_compare_fields(&http_response),
            Some(FirewallCompareType::String((
                &"139".to_string(),
                &vec!["9999".to_string()]
            )))
        );

        let http_response_field =
            HttpResponseField::HeaderVal(("not_exists".to_string(), vec!["404".to_string()]));
        assert_eq!(http_response_field.get_compare_fields(&http_response), None);
    }
}
