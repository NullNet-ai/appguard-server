use std::fs::create_dir;
use std::ops::Sub;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rpn_predicate_interpreter::PredicateEvaluator;
use serde::{Deserialize, Serialize};

use crate::constants::{FIREWALL_DIR, FIREWALL_FILE};
use crate::firewall::infix_firewall::InfixFirewall;
use crate::firewall::rules::{FirewallExpression, FirewallRule};
use crate::proto::appguard::FirewallPolicy;
use nullnet_liberror::{location, Error, ErrorHandler, Location};

#[derive(Debug, Serialize, Deserialize, Default, PartialEq)]
#[serde(transparent, rename_all = "snake_case")]
pub struct Firewall {
    pub(super) expressions: Vec<FirewallExpression>,
}

impl Firewall {
    pub fn load_from_infix(file: &str) -> Result<Self, Error> {
        let file_content = std::fs::read_to_string(file).handle_err(location!())?;
        let infix_firewall: InfixFirewall =
            serde_json::from_str(file_content.as_str()).handle_err(location!())?;

        if infix_firewall.is_valid() {
            Ok(infix_firewall.into_firewall())
        } else {
            Err("Found invalid firewall infix expression").handle_err(location!())?
        }
    }

    // fn is_valid(&self) -> bool {
    //     self.expressions
    //         .iter()
    //         .all(|expr| expr.expression.is_valid())
    // }

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
        FirewallResult::default()
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

pub fn watch_firewall(firewall: &Arc<RwLock<Firewall>>) -> Result<(), Error> {
    create_dir(FIREWALL_DIR).unwrap_or_default();

    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher =
        RecommendedWatcher::new(tx, notify::Config::default()).handle_err(location!())?;
    watcher
        .watch(FIREWALL_DIR.as_ref(), RecursiveMode::Recursive)
        .handle_err(location!())?;

    let mut last_update_time = Instant::now().sub(Duration::from_secs(60));

    loop {
        // only update firewall if the event is related to a file change
        if let Ok(Ok(Event {
            kind: EventKind::Modify(_),
            ..
        })) = rx.recv()
        {
            // debounce duplicated events
            if last_update_time.elapsed().as_millis() > 100 {
                // ensure file changes are propagated
                thread::sleep(Duration::from_millis(100));

                match Firewall::load_from_infix(FIREWALL_FILE) {
                    Ok(new_firewall) => {
                        log::info!(
                            "Updated firewall: {}",
                            serde_json::to_string(&new_firewall).unwrap_or_default()
                        );
                        *firewall.write().handle_err(location!())? = new_firewall;
                    }
                    Err(_) => {
                        log::warn!("Invalid firewall definition (ignored)");
                    }
                }

                last_update_time = Instant::now();
            }
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use rpn_predicate_interpreter::{Operator, PostfixExpression, PostfixToken};

    use crate::firewall::items::http_request::HttpRequestField;
    use crate::firewall::items::http_response::HttpResponseField;
    use crate::firewall::items::ip_info::IpInfoField;
    use crate::firewall::items::smtp_request::SmtpRequestField;
    use crate::firewall::items::smtp_response::SmtpResponseField;
    use crate::firewall::items::tcp_connection::TcpConnectionField;
    use crate::firewall::rules::{FirewallRule, FirewallRuleCondition, FirewallRuleField};
    use crate::proto::appguard::{
        AppGuardIpInfo, AppGuardSmtpRequest, AppGuardTcpConnection, AppGuardTcpInfo,
    };

    use super::*;

    const DESERIALIZED_SAMPLE_FIREWALL: std::sync::LazyLock<Firewall> =
        std::sync::LazyLock::new(|| Firewall {
            expressions: Vec::from([
                FirewallExpression {
                    policy: FirewallPolicy::Deny,
                    expression: PostfixExpression::from_tokens(Vec::from([
                        PostfixToken::Predicate(FirewallRule {
                            condition: FirewallRuleCondition::Contains,
                            field: FirewallRuleField::HttpRequest(HttpRequestField::HttpRequestUrl(
                                Vec::from([String::from(".php")]),
                            )),
                        }),
                        PostfixToken::Predicate(FirewallRule {
                            condition: FirewallRuleCondition::Equal,
                            field: FirewallRuleField::TcpConnection(TcpConnectionField::Protocol(
                                Vec::from([String::from("HTTP"), String::from("HTTPS")]),
                            )),
                        }),
                        PostfixToken::Predicate(FirewallRule {
                            condition: FirewallRuleCondition::Equal,
                            field: FirewallRuleField::IpInfo(IpInfoField::Country(Vec::from([
                                String::from("US"),
                            ]))),
                        }),
                        PostfixToken::Operator(Operator::And),
                        PostfixToken::Operator(Operator::Or),
                    ]))
                    .unwrap(),
                },
                FirewallExpression {
                    policy: FirewallPolicy::Allow,
                    expression: PostfixExpression::from_tokens(Vec::from([
                        PostfixToken::Predicate(FirewallRule {
                            condition: FirewallRuleCondition::Contains,
                            field: FirewallRuleField::SmtpRequest(SmtpRequestField::SmtpRequestBody(
                                Vec::from([String::from("Hello")]),
                            )),
                        }),
                        PostfixToken::Predicate(FirewallRule {
                            condition: FirewallRuleCondition::GreaterEqual,
                            field: FirewallRuleField::SmtpRequest(SmtpRequestField::SmtpRequestHeader((
                                String::from("From"),
                                Vec::from(["foo@bar.com".to_string(), "bar@foo.com".to_string()]),
                            ))),
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
                        }),
                        PostfixToken::Predicate(FirewallRule {
                            condition: FirewallRuleCondition::NotStartsWith,
                            field: FirewallRuleField::HttpRequest(HttpRequestField::HttpRequestQuery((
                                String::from("Name"),
                                Vec::from(["giuliano".to_string(), "giacomo".to_string()]),
                            ))),
                        }),
                        PostfixToken::Operator(Operator::Or),
                        PostfixToken::Predicate(FirewallRule {
                            condition: FirewallRuleCondition::EndsWith,
                            field: FirewallRuleField::HttpResponse(
                                HttpResponseField::HttpResponseSize(Vec::from([100, 200, 300])),
                            ),
                        }),
                        PostfixToken::Operator(Operator::Or),
                    ]))
                    .unwrap(),
                },
            ]),
        });

    const SERIALIZED_SAMPLE_FIREWALL: &str = r#"[{"policy":"deny","postfix_tokens":[{"type":"predicate","condition":"contains","field":{"type":"http_request","original_url":[".php"]}},{"type":"predicate","condition":"equal","field":{"type":"tcp_connection","protocol":["HTTP","HTTPS"]}},{"type":"predicate","condition":"equal","field":{"type":"ip_info","country":["US"]}},{"type":"operator","value":"and"},{"type":"operator","value":"or"}]},{"policy":"allow","postfix_tokens":[{"type":"predicate","condition":"contains","field":{"type":"smtp_request","body":["Hello"]}},{"type":"predicate","condition":"greater_equal","field":{"type":"smtp_request","header_val":["From",["foo@bar.com","bar@foo.com"]]}},{"type":"operator","value":"or"}]},{"policy":"deny","postfix_tokens":[{"type":"predicate","condition":"lower_than","field":{"type":"smtp_response","response_code":[205,206]}},{"type":"predicate","condition":"not_starts_with","field":{"type":"http_request","query_val":["Name",["giuliano","giacomo"]]}},{"type":"operator","value":"or"},{"type":"predicate","condition":"ends_with","field":{"type":"http_response","response_size":[100,200,300]}},{"type":"operator","value":"or"}]}]"#;

    const SERIALIZED_SAMPLE_INFIX_FIREWALL: &str = r#"[{"policy": "deny", "infix_tokens": [{"type": "predicate", "condition": "contains", "field": {"type": "http_request", "original_url": [".php"]}}, {"type": "operator", "value": "or"}, {"type": "predicate", "condition": "equal", "field": {"type": "tcp_connection", "protocol": ["HTTP", "HTTPS"]}}, {"type": "operator", "value": "and"}, {"type": "predicate", "condition": "equal", "field": {"type": "ip_info", "country": ["US"]}}]}, {"policy": "allow", "infix_tokens": [{"type": "predicate", "condition": "contains", "field": {"type": "smtp_request", "body": ["Hello"]}}, {"type": "operator", "value": "or"}, {"type": "predicate", "condition": "greater_equal", "field": {"type": "smtp_request", "header_val": ["From", ["foo@bar.com", "bar@foo.com"]]}}]}, {"policy": "deny", "infix_tokens": [{"type": "predicate", "condition": "lower_than", "field": {"type": "smtp_response", "response_code": [205, 206]}}, {"type": "operator", "value": "or"}, {"type": "predicate", "condition": "not_starts_with", "field": {"type": "http_request", "query_val": ["Name", ["giuliano", "giacomo"]]}}, {"type": "operator", "value": "or"}, {"type": "predicate", "condition": "ends_with", "field": {"type": "http_response", "response_size": [100, 200, 300]}}]}]"#;

    #[test]
    fn test_firewall_load_from_infix_json() {
        let firewall = Firewall::load_from_infix("test_material/firewall_test_1.json").unwrap();
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
    fn test_watch_firewall() {
        // verify initial firewall file
        let firewall = Firewall::load_from_infix(FIREWALL_FILE).unwrap();
        assert_eq!(firewall, *DESERIALIZED_SAMPLE_FIREWALL);

        // spawn thread
        let firewall = Arc::new(RwLock::new(firewall));
        let firewall_clone = firewall.clone();
        thread::spawn(move || {
            watch_firewall(&firewall_clone).unwrap();
        });

        // write invalid firewall and verify it's not loaded
        std::fs::write(FIREWALL_FILE, "i'm an invalid firewall").unwrap();
        thread::sleep(Duration::from_secs(1));
        assert_eq!(*firewall.read().unwrap(), *DESERIALIZED_SAMPLE_FIREWALL);

        // write a new valid firewall and verify it's loaded
        std::fs::write(FIREWALL_FILE, "[]").unwrap();
        thread::sleep(Duration::from_secs(1));
        assert_eq!(
            *firewall.read().unwrap(),
            Firewall {
                expressions: Vec::new()
            }
        );

        // write the previous valid firewall and verify it's loaded
        std::fs::write(FIREWALL_FILE, SERIALIZED_SAMPLE_INFIX_FIREWALL).unwrap();
        thread::sleep(Duration::from_secs(1));
        assert_eq!(*firewall.read().unwrap(), *DESERIALIZED_SAMPLE_FIREWALL);
    }

    #[test]
    fn test_firewall_load_from_infix_json_with_error() {
        let firewall = Firewall::load_from_infix("test_material/firewall_test_2.json");
        assert!(firewall.is_err());
    }

    #[test]
    fn test_firewall_match_items() {
        let firewall = Firewall::load_from_infix("test_material/firewall_test_1.json").unwrap();

        let mut item_1 = AppGuardTcpInfo::default();
        assert_eq!(firewall.match_item(&item_1), FirewallResult::default());

        let mut ip_info = AppGuardIpInfo::default();
        ip_info.country = Some("US".to_string());
        let mut tcp_connection = AppGuardTcpConnection::default();
        tcp_connection.protocol = "HTTP".to_string();
        item_1.ip_info = Some(ip_info);
        item_1.connection = Some(tcp_connection);

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
