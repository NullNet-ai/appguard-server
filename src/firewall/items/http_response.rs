use crate::app_context::AppContext;
use crate::firewall::header_val::HeaderVal;
use crate::firewall::rules::{
    FirewallCompareType, FirewallRule, FirewallRuleDirection, FirewallRuleField,
    FirewallRuleWithDirection,
};
use crate::helpers::get_header;
use crate::proto::appguard::{AppGuardHttpResponse, AppGuardTcpInfo};
use rpn_predicate_interpreter::PredicateEvaluator;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[allow(clippy::enum_variant_names)]
#[serde(rename_all = "snake_case")]
pub enum HttpResponseField {
    HttpResponseSize(Vec<u64>),
    HttpResponseCode(Vec<u32>),
    HttpResponseHeader(HeaderVal),
}

impl HttpResponseField {
    // pub fn get_field_name(&self) -> &str {
    //     match self {
    //         HttpResponseField::HttpResponseSize(_) => "http_response_size",
    //         HttpResponseField::HttpResponseCode(_) => "http_response_code",
    //         HttpResponseField::HttpResponseHeader(_) => "http_response_header",
    //     }
    // }

    fn get_compare_fields<'a>(
        &'a self,
        item: &'a AppGuardHttpResponse,
    ) -> Option<FirewallCompareType<'a>> {
        match self {
            HttpResponseField::HttpResponseCode(v) => {
                Some(FirewallCompareType::U32((item.code, v)))
            }
            HttpResponseField::HttpResponseSize(s) => {
                if let Ok(size) = get_header(&item.headers, "Content-Length")
                    .unwrap_or(&String::new())
                    .parse::<u64>()
                {
                    Some(FirewallCompareType::U64((size, s)))
                } else {
                    None
                }
            }
            HttpResponseField::HttpResponseHeader(HeaderVal(k, v)) => get_header(&item.headers, k)
                .map(|header| FirewallCompareType::String((header, Cow::Borrowed(v)))),
        }
    }
}

#[tonic::async_trait]
impl PredicateEvaluator for AppGuardHttpResponse {
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

        if let FirewallRuleField::HttpResponse(f) = &predicate.field {
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
        let http_response_field = HttpResponseField::HttpResponseSize(vec![931]);
        assert_eq!(
            http_response_field.get_compare_fields(&http_response),
            Some(FirewallCompareType::U64((139, &vec![931])))
        );
    }

    #[test]
    fn test_http_response_get_response_code() {
        let http_response = sample_http_response();
        let http_response_field = HttpResponseField::HttpResponseCode(vec![404]);
        assert_eq!(
            http_response_field.get_compare_fields(&http_response),
            Some(FirewallCompareType::U32((200, &vec![404])))
        );
    }

    #[test]
    fn test_http_response_get_header_val() {
        let http_response = sample_http_response();
        let http_response_field = HttpResponseField::HttpResponseHeader(HeaderVal(
            "hoST".to_string(),
            vec!["ciao".to_string()],
        ));
        assert_eq!(
            http_response_field.get_compare_fields(&http_response),
            Some(FirewallCompareType::String((
                &"example.com".to_string(),
                &vec!["ciao".to_string()]
            )))
        );

        let http_response_field = HttpResponseField::HttpResponseHeader(HeaderVal(
            "Content-Length".to_string(),
            vec!["9999".to_string()],
        ));
        assert_eq!(
            http_response_field.get_compare_fields(&http_response),
            Some(FirewallCompareType::String((
                &"139".to_string(),
                &vec!["9999".to_string()]
            )))
        );

        let http_response_field = HttpResponseField::HttpResponseHeader(HeaderVal(
            "not_exists".to_string(),
            vec!["404".to_string()],
        ));
        assert_eq!(http_response_field.get_compare_fields(&http_response), None);
    }
}
