use rpn_predicate_interpreter::PredicateEvaluator;
use serde::{Deserialize, Serialize};

use crate::firewall::rules::{
    FirewallCompareType, FirewallRuleDirection, FirewallRuleField, FirewallRuleWithDirection,
};
use crate::proto::appguard::AppGuardTcpConnection;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum TcpConnectionField {
    SourceIp(Vec<String>),
    DestinationIp(Vec<String>),
    SourcePort(Vec<u32>),
    DestinationPort(Vec<u32>),
    Protocol(Vec<String>),
}

impl TcpConnectionField {
    // pub fn get_field_name(&self) -> &str {
    //     match self {
    //         TcpConnectionField::SourceIp(_) => "source_ip",
    //         TcpConnectionField::DestinationIp(_) => "destination_ip",
    //         TcpConnectionField::SourcePort(_) => "source_port",
    //         TcpConnectionField::DestinationPort(_) => "destination_port",
    //         TcpConnectionField::Protocol(_) => "protocol",
    //     }
    // }

    fn get_compare_fields<'a>(
        &'a self,
        item: &'a AppGuardTcpConnection,
        direction: &FirewallRuleDirection,
    ) -> Option<FirewallCompareType<'a>> {
        match self {
            TcpConnectionField::SourceIp(v) => match direction {
                FirewallRuleDirection::In => item.source_ip.as_ref(),
                FirewallRuleDirection::Out => item.destination_ip.as_ref(),
            }
            .map(|ip| FirewallCompareType::String((ip, v))),
            TcpConnectionField::DestinationIp(v) => match direction {
                FirewallRuleDirection::In => item.destination_ip.as_ref(),
                FirewallRuleDirection::Out => item.source_ip.as_ref(),
            }
            .map(|ip| FirewallCompareType::String((ip, v))),
            TcpConnectionField::SourcePort(v) => match direction {
                FirewallRuleDirection::In => item.source_port,
                FirewallRuleDirection::Out => item.destination_port,
            }
            .map(|p| FirewallCompareType::U32((p, v))),
            TcpConnectionField::DestinationPort(v) => match direction {
                FirewallRuleDirection::In => item.destination_port,
                FirewallRuleDirection::Out => item.source_port,
            }
            .map(|p| FirewallCompareType::U32((p, v))),
            TcpConnectionField::Protocol(v) => {
                Some(FirewallCompareType::String((&item.protocol, v)))
            }
        }
    }
}

impl<'a> PredicateEvaluator for &'a AppGuardTcpConnection {
    type Predicate = FirewallRuleWithDirection<'a>;
    type Reason = String;

    fn evaluate_predicate(&self, predicate: &Self::Predicate) -> bool {
        if let FirewallRuleField::TcpConnection(f) = &predicate.rule.field {
            return predicate
                .rule
                .condition
                .compare(f.get_compare_fields(self, &predicate.direction));
        }
        false
    }

    fn get_reason(&self, predicate: &Self::Predicate) -> Self::Reason {
        serde_json::to_string(predicate.rule).unwrap_or_default()
    }

    fn get_remote_ip(&self) -> String {
        self.source_ip.clone().unwrap_or_default()
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
    fn test_tcp_connection_get_source_ip() {
        let tcp_connection = sample_tcp_connection();
        let tcp_connection_field = TcpConnectionField::SourceIp(vec!["8.8.8.8".to_string()]);
        for direction in [FirewallRuleDirection::In, FirewallRuleDirection::In].iter() {
            let ip = match direction {
                FirewallRuleDirection::In => "1.1.1.1",
                FirewallRuleDirection::Out => "2.2.2.2",
            };
            assert_eq!(
                tcp_connection_field.get_compare_fields(&tcp_connection, &direction),
                Some(FirewallCompareType::String((
                    &ip.to_string(),
                    &vec!["8.8.8.8".to_string()]
                )))
            );
        }
    }

    #[test]
    fn test_tcp_connection_get_destination_ip() {
        let tcp_connection = sample_tcp_connection();
        let tcp_connection_field = TcpConnectionField::DestinationIp(vec!["8.8.8.8".to_string()]);
        for direction in [FirewallRuleDirection::In, FirewallRuleDirection::In].iter() {
            let ip = match direction {
                FirewallRuleDirection::In => "2.2.2.2",
                FirewallRuleDirection::Out => "1.1.1.1",
            };
            assert_eq!(
                tcp_connection_field.get_compare_fields(&tcp_connection, &direction),
                Some(FirewallCompareType::String((
                    &ip.to_string(),
                    &vec!["8.8.8.8".to_string()]
                )))
            );
        }
    }

    #[test]
    fn test_tcp_connection_get_source_port() {
        let tcp_connection = sample_tcp_connection();
        let tcp_connection_field = TcpConnectionField::SourcePort(vec![8080]);
        for direction in [FirewallRuleDirection::In, FirewallRuleDirection::In].iter() {
            let p = match direction {
                FirewallRuleDirection::In => 1234,
                FirewallRuleDirection::Out => 5678,
            };
            assert_eq!(
                tcp_connection_field.get_compare_fields(&tcp_connection, &direction),
                Some(FirewallCompareType::U32((p, &vec![8080])))
            );
        }
    }

    #[test]
    fn test_tcp_connection_get_destination_port() {
        let tcp_connection = sample_tcp_connection();
        let tcp_connection_field = TcpConnectionField::DestinationPort(vec![8080]);
        for direction in [FirewallRuleDirection::In, FirewallRuleDirection::In].iter() {
            let p = match direction {
                FirewallRuleDirection::In => 5678,
                FirewallRuleDirection::Out => 1234,
            };
            assert_eq!(
                tcp_connection_field.get_compare_fields(&tcp_connection, &direction),
                Some(FirewallCompareType::U32((p, &vec![8080])))
            );
        }
    }

    #[test]
    fn test_tcp_connection_get_protocol() {
        let tcp_connection = sample_tcp_connection();
        let tcp_connection_field =
            TcpConnectionField::Protocol(vec!["SMTP".to_string(), "ESMTP".to_string()]);
        for direction in [FirewallRuleDirection::In, FirewallRuleDirection::In].iter() {
            assert_eq!(
                tcp_connection_field.get_compare_fields(&tcp_connection, direction),
                Some(FirewallCompareType::String((
                    &"HTTP".to_string(),
                    &vec!["SMTP".to_string(), "ESMTP".to_string()]
                )))
            );
        }
    }
}
