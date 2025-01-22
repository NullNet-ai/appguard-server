use rpn_predicate_interpreter::PredicateEvaluator;
use serde::{Deserialize, Serialize};

use crate::firewall::rules::{FirewallCompareType, FirewallRule, FirewallRuleField};
use crate::helpers::get_header;
use crate::proto::appguard::{AppGuardHttpRequest, AppGuardTcpInfo};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HttpRequestField {
    OriginalUrl(Vec<String>),
    Method(Vec<String>),
    QueryVal((String, Vec<String>)),
    Cookie(Vec<String>),
    HeaderVal((String, Vec<String>)),
    Body(Vec<String>),
    BodyLen(Vec<usize>),
    UserAgent(Vec<String>),
}

impl HttpRequestField {
    pub fn get_field_name(&self) -> &str {
        match self {
            HttpRequestField::OriginalUrl(_) => "original_url",
            HttpRequestField::Method(_) => "method",
            HttpRequestField::QueryVal(_) => "query_val",
            HttpRequestField::Cookie(_) => "cookie",
            HttpRequestField::HeaderVal(_) => "header_val",
            HttpRequestField::Body(_) => "body",
            HttpRequestField::BodyLen(_) => "body_len",
            HttpRequestField::UserAgent(_) => "user_agent",
        }
    }

    fn get_compare_fields<'a>(
        &'a self,
        item: &'a AppGuardHttpRequest,
    ) -> Option<FirewallCompareType<'a>> {
        match self {
            HttpRequestField::OriginalUrl(v) => {
                Some(FirewallCompareType::String((&item.original_url, v)))
            }
            HttpRequestField::Method(v) => Some(FirewallCompareType::String((&item.method, v))),
            HttpRequestField::QueryVal((k, v)) => {
                get_header(&item.query, k).map(|query| FirewallCompareType::String((query, v)))
            }
            HttpRequestField::Cookie(v) => get_header(&item.headers, "Cookie")
                .map(|cookie| FirewallCompareType::String((cookie, v))),
            HttpRequestField::HeaderVal((k, v)) => {
                get_header(&item.headers, k).map(|header| FirewallCompareType::String((header, v)))
            }
            HttpRequestField::Body(v) => item
                .body
                .as_ref()
                .map(|body| FirewallCompareType::String((body, v))),
            HttpRequestField::BodyLen(v) => item
                .body
                .as_ref()
                .map(|body| FirewallCompareType::Usize((body.len(), v))),
            HttpRequestField::UserAgent(v) => get_header(&item.headers, "User-Agent")
                .map(|user_agent| FirewallCompareType::String((user_agent, v))),
        }
    }
}

impl PredicateEvaluator for AppGuardHttpRequest {
    type Predicate = FirewallRule;
    type Reason = String;

    fn evaluate_predicate(&self, predicate: &Self::Predicate) -> bool {
        match &predicate.field {
            FirewallRuleField::HttpRequest(f) => {
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

    fn sample_http_request() -> AppGuardHttpRequest {
        let mut headers = HashMap::new();
        headers.insert("User-Agent".to_string(), "Mozilla/5.0".to_string());
        headers.insert("Cookie".to_string(), "biscuits".to_string());
        headers.insert("Host".to_string(), "example.com".to_string());

        let mut query = HashMap::new();
        query.insert("name".to_string(), "John".to_string());

        AppGuardHttpRequest {
            original_url: "https://example.com".to_string(),
            method: "GET".to_string(),
            query,
            headers,
            body: Some("Hello, World!".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn test_http_request_get_original_url() {
        let http_request = sample_http_request();
        let http_request_field = HttpRequestField::OriginalUrl(vec!["test.com".to_string()]);
        assert_eq!(
            http_request_field.get_compare_fields(&http_request),
            Some(FirewallCompareType::String((
                &"https://example.com".to_string(),
                &vec!["test.com".to_string()]
            )))
        );
    }

    #[test]
    fn test_http_request_get_method() {
        let http_request = sample_http_request();
        let http_request_field =
            HttpRequestField::Method(vec!["GET".to_string(), "POST".to_string()]);
        assert_eq!(
            http_request_field.get_compare_fields(&http_request),
            Some(FirewallCompareType::String((
                &"GET".to_string(),
                &vec!["GET".to_string(), "POST".to_string()]
            )))
        );
    }

    #[test]
    fn test_http_request_get_query_val() {
        let http_request = sample_http_request();
        let http_request_field =
            HttpRequestField::QueryVal(("name".to_string(), vec!["Bob".to_string()]));
        assert_eq!(
            http_request_field.get_compare_fields(&http_request),
            Some(FirewallCompareType::String((
                &"John".to_string(),
                &vec!["Bob".to_string()]
            )))
        );

        let http_request_field =
            HttpRequestField::QueryVal(("surname".to_string(), vec!["Smith".to_string()]));
        assert_eq!(http_request_field.get_compare_fields(&http_request), None);
    }

    #[test]
    fn test_http_request_get_cookie() {
        let http_request = sample_http_request();
        let http_request_field = HttpRequestField::Cookie(vec!["awesome_cookie_99".to_string()]);
        assert_eq!(
            http_request_field.get_compare_fields(&http_request),
            Some(FirewallCompareType::String((
                &"biscuits".to_string(),
                &vec!["awesome_cookie_99".to_string()]
            )))
        );
    }

    #[test]
    fn test_http_request_get_header_val() {
        let http_request = sample_http_request();
        let http_request_field =
            HttpRequestField::HeaderVal(("cooKiE".to_string(), vec!["Marlon".to_string()]));
        assert_eq!(
            http_request_field.get_compare_fields(&http_request),
            Some(FirewallCompareType::String((
                &"biscuits".to_string(),
                &vec!["Marlon".to_string()]
            )))
        );

        let http_request_field =
            HttpRequestField::HeaderVal(("host".to_string(), vec!["sample_host".to_string()]));
        assert_eq!(
            http_request_field.get_compare_fields(&http_request),
            Some(FirewallCompareType::String((
                &"example.com".to_string(),
                &vec!["sample_host".to_string()]
            )))
        );

        let http_request_field =
            HttpRequestField::HeaderVal(("not_exists".to_string(), vec!["404".to_string()]));
        assert_eq!(http_request_field.get_compare_fields(&http_request), None);
    }

    #[test]
    fn test_http_request_get_body() {
        let http_request = sample_http_request();
        let http_request_field =
            HttpRequestField::Body(vec!["Hello".to_string(), "World!".to_string()]);
        assert_eq!(
            http_request_field.get_compare_fields(&http_request),
            Some(FirewallCompareType::String((
                &"Hello, World!".to_string(),
                &vec!["Hello".to_string(), "World!".to_string()]
            )))
        );
    }

    #[test]
    fn test_http_request_get_body_len() {
        let http_request = sample_http_request();
        let http_request_field = HttpRequestField::BodyLen(vec![7, 99]);
        assert_eq!(
            http_request_field.get_compare_fields(&http_request),
            Some(FirewallCompareType::Usize((13, &vec![7, 99])))
        );
    }

    #[test]
    fn test_http_request_get_user_agent() {
        let http_request = sample_http_request();
        let http_request_field =
            HttpRequestField::UserAgent(vec!["awesome_user_agent".to_string()]);
        assert_eq!(
            http_request_field.get_compare_fields(&http_request),
            Some(FirewallCompareType::String((
                &"Mozilla/5.0".to_string(),
                &vec!["awesome_user_agent".to_string()]
            )))
        );
    }
}
