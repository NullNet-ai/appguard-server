use rpn_predicate_interpreter::PredicateEvaluator;
use serde::{Deserialize, Serialize};

use crate::firewall::infix_firewall::InfixFirewall;
use crate::firewall::rules::{FirewallExpression, FirewallRule};
use crate::proto::appguard_commands::FirewallPolicy;
use nullnet_liberror::{location, Error, ErrorHandler, Location};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Firewall {
    pub(crate) timeout: u32,
    pub(crate) default_policy: FirewallPolicy,
    pub(super) expressions: Vec<FirewallExpression>,
}

impl Firewall {
    pub fn from_infix(infix: &str) -> Result<Self, Error> {
        let infix_firewall: InfixFirewall = serde_json::from_str(infix).handle_err(location!())?;

        if infix_firewall.is_valid() {
            Ok(infix_firewall.into_firewall())
        } else {
            Err("Found invalid firewall infix expression").handle_err(location!())?
        }
    }

    pub fn from_postfix(postfix: &str) -> Result<Self, Error> {
        let firewall: Firewall = serde_json::from_str(postfix).handle_err(location!())?;

        if firewall.is_valid() {
            Ok(firewall)
        } else {
            Err("Found invalid firewall postfix expression").handle_err(location!())?
        }
    }

    fn is_valid(&self) -> bool {
        self.expressions
            .iter()
            .all(|expr| expr.expression.is_valid())
    }

    pub fn match_item<I: PredicateEvaluator<Predicate = FirewallRule, Reason = String>>(
        &self,
        item: &I,
    ) -> FirewallResult {
        // first let's check if this is blacklisted
        if item.is_blacklisted() {
            return FirewallResult::new(FirewallPolicy::Deny, vec!["blacklist".to_string()]);
        }
        // if not blacklisted, check the firewall expressions one by one
        for expr in &self.expressions {
            let (result, reasons) = expr.expression.evaluate(item);
            if result {
                return FirewallResult::new(expr.policy, reasons);
            }
        }
        FirewallResult {
            policy: self.default_policy,
            reasons: vec![],
        }
    }
}

impl Default for Firewall {
    fn default() -> Self {
        Self {
            timeout: 1000, // default timeout in milliseconds
            default_policy: FirewallPolicy::Allow,
            expressions: Vec::new(),
        }
    }
}

#[derive(PartialEq, Debug)]
pub struct FirewallResult {
    pub policy: FirewallPolicy,
    pub reasons: Vec<String>,
}

impl FirewallResult {
    pub fn new(policy: FirewallPolicy, reasons: Vec<String>) -> Self {
        Self { policy, reasons }
    }
}

impl Default for FirewallResult {
    fn default() -> Self {
        Self::new(FirewallPolicy::Allow, Vec::new())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::firewall::header_val::HeaderVal;
    use crate::firewall::items::http_request::HttpRequestField;
    use crate::firewall::items::http_response::HttpResponseField;
    use crate::firewall::items::ip_info::IpInfoField;
    use crate::firewall::items::smtp_request::SmtpRequestField;
    use crate::firewall::items::smtp_response::SmtpResponseField;
    use crate::firewall::items::tcp_connection::TcpConnectionField;
    use crate::firewall::rules::{
        FirewallRule, FirewallRuleCondition, FirewallRuleDirection, FirewallRuleField,
    };
    use crate::proto::appguard::{
        AppGuardHttpRequest, AppGuardIpInfo, AppGuardSmtpRequest, AppGuardTcpConnection,
        AppGuardTcpInfo,
    };
    use rpn_predicate_interpreter::{Operator, PostfixExpression, PostfixToken};

    use super::*;

    const DESERIALIZED_SAMPLE_FIREWALL: std::sync::LazyLock<Firewall> =
        std::sync::LazyLock::new(|| Firewall {
            timeout: 1000,
            default_policy: FirewallPolicy::Allow,
            expressions: Vec::from([
                FirewallExpression {
                    policy: FirewallPolicy::Deny,
                    expression: PostfixExpression::from_tokens(Vec::from([
                        PostfixToken::Predicate(FirewallRule {
                            condition: FirewallRuleCondition::Equal,
                            field: FirewallRuleField::TcpConnection(TcpConnectionField::Protocol(
                                Vec::from([String::from("HTTP"), String::from("HTTPS")]),
                            )),
                            direction: Some(FirewallRuleDirection::In),
                        }),
                        PostfixToken::Predicate(FirewallRule {
                            condition: FirewallRuleCondition::Contains,
                            field: FirewallRuleField::HttpRequest(
                                HttpRequestField::HttpRequestUrl(Vec::from([String::from(".php")])),
                            ),
                            direction: None,
                        }),
                        PostfixToken::Operator(Operator::Or),
                        PostfixToken::Predicate(FirewallRule {
                            condition: FirewallRuleCondition::Equal,
                            field: FirewallRuleField::IpInfo(IpInfoField::Country(Vec::from([
                                String::from("US"),
                            ]))),
                            direction: None,
                        }),
                        PostfixToken::Operator(Operator::And),
                    ]))
                    .unwrap(),
                },
                FirewallExpression {
                    policy: FirewallPolicy::Allow,
                    expression: PostfixExpression::from_tokens(Vec::from([
                        PostfixToken::Predicate(FirewallRule {
                            condition: FirewallRuleCondition::Contains,
                            field: FirewallRuleField::SmtpRequest(
                                SmtpRequestField::SmtpRequestBody(Vec::from([String::from(
                                    "Hello",
                                )])),
                            ),
                            direction: None,
                        }),
                        PostfixToken::Predicate(FirewallRule {
                            condition: FirewallRuleCondition::GreaterEqual,
                            field: FirewallRuleField::SmtpRequest(
                                SmtpRequestField::SmtpRequestHeader(HeaderVal(
                                    String::from("From"),
                                    Vec::from([
                                        "foo@bar.com".to_string(),
                                        "bar@foo.com".to_string(),
                                        "foo@baz.com".to_string(),
                                    ]),
                                )),
                            ),
                            direction: None,
                        }),
                        PostfixToken::Operator(Operator::Or),
                    ]))
                    .unwrap(),
                },
                FirewallExpression {
                    policy: FirewallPolicy::Deny,
                    expression: PostfixExpression::from_tokens(Vec::from([
                        PostfixToken::Predicate(FirewallRule {
                            condition: FirewallRuleCondition::LowerThan,
                            field: FirewallRuleField::SmtpResponse(
                                SmtpResponseField::SmtpResponseCode(Vec::from([205, 206])),
                            ),
                            direction: None,
                        }),
                        PostfixToken::Predicate(FirewallRule {
                            condition: FirewallRuleCondition::NotStartsWith,
                            field: FirewallRuleField::HttpRequest(
                                HttpRequestField::HttpRequestQuery(HeaderVal(
                                    String::from("Name"),
                                    Vec::from(["giuliano".to_string(), "giacomo".to_string()]),
                                )),
                            ),
                            direction: None,
                        }),
                        PostfixToken::Operator(Operator::Or),
                        PostfixToken::Predicate(FirewallRule {
                            condition: FirewallRuleCondition::EndsWith,
                            field: FirewallRuleField::HttpResponse(
                                HttpResponseField::HttpResponseSize(Vec::from([100, 200, 300])),
                            ),
                            direction: None,
                        }),
                        PostfixToken::Operator(Operator::Or),
                    ]))
                    .unwrap(),
                },
            ]),
        });

    const SERIALIZED_SAMPLE_FIREWALL: &str = r#"{"timeout":1000,"default_policy":"allow","expressions":[{"policy":"deny","postfix_tokens":[{"type":"predicate","condition":"equal","protocol":["HTTP","HTTPS"],"direction":"in"},{"type":"predicate","condition":"contains","http_request_url":[".php"]},{"type":"operator","value":"or"},{"type":"predicate","condition":"equal","country":["US"]},{"type":"operator","value":"and"}]},{"policy":"allow","postfix_tokens":[{"type":"predicate","condition":"contains","smtp_request_body":["Hello"]},{"type":"predicate","condition":"greater_equal","smtp_request_header":{"From":["foo@bar.com","bar@foo.com","foo@baz.com"]}},{"type":"operator","value":"or"}]},{"policy":"deny","postfix_tokens":[{"type":"predicate","condition":"lower_than","smtp_response_code":[205,206]},{"type":"predicate","condition":"not_starts_with","http_request_query":{"Name":["giuliano","giacomo"]}},{"type":"operator","value":"or"},{"type":"predicate","condition":"ends_with","http_response_size":[100,200,300]},{"type":"operator","value":"or"}]}]}"#;

    #[test]
    fn test_firewall_load_from_infix_json() {
        // for the firewall in the root directory, just verify the file is valid
        let content = std::fs::read_to_string("firewall.json").unwrap();
        let _ = Firewall::from_infix(&content).unwrap();

        let content = std::fs::read_to_string("test_material/firewall_test_1.json").unwrap();
        let firewall = Firewall::from_infix(&content).unwrap();
        assert_eq!(firewall, *DESERIALIZED_SAMPLE_FIREWALL);
        assert_eq!(
            serde_json::to_string(&firewall).unwrap(),
            SERIALIZED_SAMPLE_FIREWALL
        );
        assert_eq!(
            serde_json::from_str::<Firewall>(SERIALIZED_SAMPLE_FIREWALL).unwrap(),
            *DESERIALIZED_SAMPLE_FIREWALL
        );
    }

    #[test]
    fn test_firewall_load_from_infix_json_with_error() {
        let content = std::fs::read_to_string("test_material/firewall_test_2.json").unwrap();
        let firewall = Firewall::from_infix(&content);
        assert!(firewall.is_err());
    }

    #[test]
    fn test_firewall_match_items() {
        let content = std::fs::read_to_string("test_material/firewall_test_1.json").unwrap();
        let firewall = Firewall::from_infix(&content).unwrap();

        let mut item_1 = AppGuardHttpRequest::default();
        assert_eq!(firewall.match_item(&item_1), FirewallResult::default());

        let mut tcp_info = AppGuardTcpInfo::default();
        let mut ip_info = AppGuardIpInfo::default();
        ip_info.country = Some("US".to_string());
        tcp_info.ip_info = Some(ip_info);
        let mut tcp_connection = AppGuardTcpConnection::default();
        tcp_connection.protocol = "HTTP".to_string();
        tcp_info.connection = Some(tcp_connection);
        item_1.tcp_info = Some(tcp_info);

        assert_eq!(
            firewall.match_item(&item_1),
            FirewallResult::new(
                FirewallPolicy::Deny,
                vec!["protocol".to_string(), "country".to_string()]
            )
        );

        let mut item_2 = AppGuardSmtpRequest::default();
        assert_eq!(firewall.match_item(&item_2), FirewallResult::default());

        item_2.body = Some("Hey! Hello World!!!".to_string());
        assert_eq!(
            firewall.match_item(&item_2),
            FirewallResult::new(FirewallPolicy::Allow, vec!["smtp_request_body".to_string()])
        );

        item_2.body = Some("Hey! World!!!".to_string());
        assert_eq!(firewall.match_item(&item_2), FirewallResult::default());
    }
}
