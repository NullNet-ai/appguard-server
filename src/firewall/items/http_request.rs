use crate::app_context::AppContext;
use crate::firewall::header_val::HeaderVal;
use crate::firewall::rules::{
    FirewallCompareType, FirewallRule, FirewallRuleDirection, FirewallRuleField,
    FirewallRuleWithDirection,
};
use crate::helpers::get_header;
use crate::proto::appguard::{AppGuardHttpRequest, AppGuardTcpInfo};
use rpn_predicate_interpreter::PredicateEvaluator;
use serde::{Deserialize, Serialize};
use async_trait::async_trait;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[allow(clippy::enum_variant_names)]
#[serde(rename_all = "snake_case")]
pub enum HttpRequestField {
    HttpRequestUrl(Vec<String>),
    HttpRequestMethod(Vec<String>),
    HttpRequestQuery(HeaderVal),
    HttpRequestCookie(Vec<String>),
    HttpRequestHeader(HeaderVal),
    HttpRequestBody(Vec<String>),
    HttpRequestBodyLen(Vec<usize>),
    HttpRequestUserAgent(Vec<String>),
}

impl HttpRequestField {
    // pub fn get_field_name(&self) -> &str {
    //     match self {
    //         HttpRequestField::HttpRequestUrl(_) => "http_request_url",
    //         HttpRequestField::HttpRequestMethod(_) => "http_request_method",
    //         HttpRequestField::HttpRequestQuery(_) => "http_request_query",
    //         HttpRequestField::HttpRequestCookie(_) => "http_request_cookie",
    //         HttpRequestField::HttpRequestHeader(_) => "http_request_header",
    //         HttpRequestField::HttpRequestBody(_) => "http_request_body",
    //         HttpRequestField::HttpRequestBodyLen(_) => "http_request_body_len",
    //         HttpRequestField::HttpRequestUserAgent(_) => "http_request_user_agent",
    //     }
    // }

    fn get_compare_fields<'a>(
        &'a self,
        item: &'a AppGuardHttpRequest,
    ) -> Option<FirewallCompareType<'a>> {
        match self {
            HttpRequestField::HttpRequestUrl(v) => {
                Some(FirewallCompareType::String((&item.original_url, v)))
            }
            HttpRequestField::HttpRequestMethod(v) => {
                Some(FirewallCompareType::String((&item.method, v)))
            }
            HttpRequestField::HttpRequestQuery(HeaderVal(k, v)) => {
                get_header(&item.query, k).map(|query| FirewallCompareType::String((query, v)))
            }
            HttpRequestField::HttpRequestCookie(v) => get_header(&item.headers, "Cookie")
                .map(|cookie| FirewallCompareType::String((cookie, v))),
            HttpRequestField::HttpRequestHeader(HeaderVal(k, v)) => {
                get_header(&item.headers, k).map(|header| FirewallCompareType::String((header, v)))
            }
            HttpRequestField::HttpRequestBody(v) => item
                .body
                .as_ref()
                .map(|body| FirewallCompareType::String((body, v))),
            HttpRequestField::HttpRequestBodyLen(v) => item
                .body
                .as_ref()
                .map(|body| FirewallCompareType::Usize((body.len(), v))),
            HttpRequestField::HttpRequestUserAgent(v) => get_header(&item.headers, "User-Agent")
                .map(|user_agent| FirewallCompareType::String((user_agent, v))),
        }
    }
}

#[async_trait(?Send)]
impl PredicateEvaluator for AppGuardHttpRequest {
    type Predicate = FirewallRule;
    type Reason = String;
    type Context = AppContext;

    async fn evaluate_predicate(&self, predicate: &Self::Predicate, context: &Self::Context) -> bool {
        if predicate.direction == Some(FirewallRuleDirection::Out) {
            return false;
        }

        if let FirewallRuleField::HttpRequest(f) = &predicate.field {
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
                ).await
        }
    }

    fn get_reason(&self, predicate: &Self::Predicate) -> Self::Reason {
        serde_json::to_string(predicate).unwrap_or_default()
    }

    fn is_blacklisted(&self) -> bool {
        self.tcp_info
            .as_ref()
            .unwrap_or(&AppGuardTcpInfo::default())
            .is_blacklisted()
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
        let http_request_field = HttpRequestField::HttpRequestUrl(vec!["test.com".to_string()]);
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
            HttpRequestField::HttpRequestMethod(vec!["GET".to_string(), "POST".to_string()]);
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
        let http_request_field = HttpRequestField::HttpRequestQuery(HeaderVal(
            "name".to_string(),
            vec!["Bob".to_string()],
        ));
        assert_eq!(
            http_request_field.get_compare_fields(&http_request),
            Some(FirewallCompareType::String((
                &"John".to_string(),
                &vec!["Bob".to_string()]
            )))
        );

        let http_request_field = HttpRequestField::HttpRequestQuery(HeaderVal(
            "surname".to_string(),
            vec!["Smith".to_string()],
        ));
        assert_eq!(http_request_field.get_compare_fields(&http_request), None);
    }

    #[test]
    fn test_http_request_get_cookie() {
        let http_request = sample_http_request();
        let http_request_field =
            HttpRequestField::HttpRequestCookie(vec!["awesome_cookie_99".to_string()]);
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
        let http_request_field = HttpRequestField::HttpRequestHeader(HeaderVal(
            "cooKiE".to_string(),
            vec!["Marlon".to_string()],
        ));
        assert_eq!(
            http_request_field.get_compare_fields(&http_request),
            Some(FirewallCompareType::String((
                &"biscuits".to_string(),
                &vec!["Marlon".to_string()]
            )))
        );

        let http_request_field = HttpRequestField::HttpRequestHeader(HeaderVal(
            "host".to_string(),
            vec!["sample_host".to_string()],
        ));
        assert_eq!(
            http_request_field.get_compare_fields(&http_request),
            Some(FirewallCompareType::String((
                &"example.com".to_string(),
                &vec!["sample_host".to_string()]
            )))
        );

        let http_request_field = HttpRequestField::HttpRequestHeader(HeaderVal(
            "not_exists".to_string(),
            vec!["404".to_string()],
        ));
        assert_eq!(http_request_field.get_compare_fields(&http_request), None);
    }

    #[test]
    fn test_http_request_get_body() {
        let http_request = sample_http_request();
        let http_request_field =
            HttpRequestField::HttpRequestBody(vec!["Hello".to_string(), "World!".to_string()]);
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
        let http_request_field = HttpRequestField::HttpRequestBodyLen(vec![7, 99]);
        assert_eq!(
            http_request_field.get_compare_fields(&http_request),
            Some(FirewallCompareType::Usize((13, &vec![7, 99])))
        );
    }

    #[test]
    fn test_http_request_get_user_agent() {
        let http_request = sample_http_request();
        let http_request_field =
            HttpRequestField::HttpRequestUserAgent(vec!["awesome_user_agent".to_string()]);
        assert_eq!(
            http_request_field.get_compare_fields(&http_request),
            Some(FirewallCompareType::String((
                &"Mozilla/5.0".to_string(),
                &vec!["awesome_user_agent".to_string()]
            )))
        );
    }
}
