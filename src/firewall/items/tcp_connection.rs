use rpn_predicate_interpreter::PredicateEvaluator;
use serde::{Deserialize, Serialize};

use crate::firewall::rules::{FirewallCompareType, FirewallRule, FirewallRuleField};
use crate::proto::appguard::AppGuardTcpConnection;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum TcpConnectionField {
    Ip(Vec<String>),
    Port(Vec<u32>),
    Protocol(Vec<String>),
}

impl TcpConnectionField {
    pub fn get_field_name(&self) -> &str {
        match self {
            TcpConnectionField::Ip(_) => "ip",
            TcpConnectionField::Port(_) => "port",
            TcpConnectionField::Protocol(_) => "protocol",
        }
    }

    fn get_compare_fields<'a>(
        &'a self,
        item: &'a AppGuardTcpConnection,
    ) -> Option<FirewallCompareType<'a>> {
        match self {
            TcpConnectionField::Ip(v) => item
                .source_ip
                .as_ref()
                .map(|ip| FirewallCompareType::String((ip, v))),
            TcpConnectionField::Port(v) => item
                .source_port
                .as_ref()
                .map(|port| FirewallCompareType::U32((*port, v))),
            TcpConnectionField::Protocol(v) => {
                Some(FirewallCompareType::String((&item.protocol, v)))
            }
        }
    }
}

impl PredicateEvaluator for AppGuardTcpConnection {
    type Predicate = FirewallRule;
    type Reason = String;

    fn evaluate_predicate(&self, predicate: &Self::Predicate) -> bool {
        if let FirewallRuleField::TcpConnection(f) = &predicate.field {
            return predicate.condition.compare(f.get_compare_fields(self));
        }
        false
    }

    fn get_reason(&self, predicate: &Self::Predicate) -> Self::Reason {
        predicate.field.get_field_name()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn sample_tcp_connection() -> AppGuardTcpConnection {
        AppGuardTcpConnection {
            source_ip: Some("1.1.1.1".to_string()),
            source_port: Some(1234),
            destination_ip: Some("2.2.2.2".to_string()),
            destination_port: Some(5678),
            protocol: "HTTP".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn test_tcp_connection_get_ip() {
        let tcp_connection = sample_tcp_connection();
        let tcp_connection_field = TcpConnectionField::Ip(vec!["8.8.8.8".to_string()]);
        assert_eq!(
            tcp_connection_field.get_compare_fields(&tcp_connection),
            Some(FirewallCompareType::String((
                &"1.1.1.1".to_string(),
                &vec!["8.8.8.8".to_string()]
            )))
        );
    }

    #[test]
    fn test_tcp_connection_get_port() {
        let tcp_connection = sample_tcp_connection();
        let tcp_connection_field = TcpConnectionField::Port(vec![80, 443, 8080]);
        assert_eq!(
            tcp_connection_field.get_compare_fields(&tcp_connection),
            Some(FirewallCompareType::U32((1234, &vec![80, 443, 8080])))
        );
    }

    #[test]
    fn test_tcp_connection_get_protocol() {
        let tcp_connection = sample_tcp_connection();
        let tcp_connection_field =
            TcpConnectionField::Protocol(vec!["SMTP".to_string(), "ESMTP".to_string()]);
        assert_eq!(
            tcp_connection_field.get_compare_fields(&tcp_connection),
            Some(FirewallCompareType::String((
                &"HTTP".to_string(),
                &vec!["SMTP".to_string(), "ESMTP".to_string()]
            )))
        );
    }
}
