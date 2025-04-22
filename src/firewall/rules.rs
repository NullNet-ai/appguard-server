use rpn_predicate_interpreter::PostfixExpression;
use serde::{Deserialize, Serialize};

use crate::firewall::items::http_request::HttpRequestField;
use crate::firewall::items::http_response::HttpResponseField;
use crate::firewall::items::ip_info::IpInfoField;
use crate::firewall::items::smtp_request::SmtpRequestField;
use crate::firewall::items::smtp_response::SmtpResponseField;
use crate::firewall::items::tcp_connection::TcpConnectionField;
use crate::proto::appguard::FirewallPolicy;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct FirewallExpression {
    pub(super) policy: FirewallPolicy,
    #[serde(flatten)]
    pub(super) expression: PostfixExpression<FirewallRule>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct FirewallRule {
    pub(crate) condition: FirewallRuleCondition,
    #[serde(flatten)]
    pub(crate) field: FirewallRuleField,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) direction: Option<FirewallRuleDirection>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum FirewallRuleDirection {
    In,
    Out,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(untagged)]
pub enum FirewallRuleField {
    TcpConnection(TcpConnectionField),
    IpInfo(IpInfoField),
    HttpRequest(HttpRequestField),
    HttpResponse(HttpResponseField),
    SmtpRequest(SmtpRequestField),
    SmtpResponse(SmtpResponseField),
}

impl FirewallRuleField {
    pub fn get_field_name(&self) -> String {
        match self {
            FirewallRuleField::TcpConnection(f) => f.get_field_name(),
            FirewallRuleField::IpInfo(f) => f.get_field_name(),
            FirewallRuleField::HttpRequest(f) => f.get_field_name(),
            FirewallRuleField::HttpResponse(f) => f.get_field_name(),
            FirewallRuleField::SmtpRequest(f) => f.get_field_name(),
            FirewallRuleField::SmtpResponse(f) => f.get_field_name(),
        }
        .to_string()
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum FirewallRuleCondition {
    Equal,
    NotEqual,
    GreaterThan,
    LowerThan,
    GreaterEqual,
    LowerEqual,
    Contains,
    NotContains,
    StartsWith,
    NotStartsWith,
    EndsWith,
    NotEndsWith,
}

impl FirewallRuleCondition {
    pub fn compare(&self, firewall_compare_type: Option<FirewallCompareType>) -> bool {
        if let Some(fields) = firewall_compare_type {
            return match fields {
                FirewallCompareType::String((l, r)) => self.compare_vec(l, r),
                FirewallCompareType::Usize((l, r)) => self.compare_vec(&l, r),
                FirewallCompareType::U32((l, r)) => self.compare_vec(&l, r),
                FirewallCompareType::U64((l, r)) => self.compare_vec(&l, r),
            };
        }
        false
    }

    fn compare_vec<T: PartialEq + PartialOrd + ToString>(&self, left: &T, right: &[T]) -> bool {
        match self {
            Self::Equal | Self::Contains | Self::StartsWith | Self::EndsWith => {
                right.iter().any(|v| self.compare_single(left, v))
            }
            Self::NotEqual
            | Self::GreaterThan
            | Self::LowerThan
            | Self::GreaterEqual
            | Self::LowerEqual
            | Self::NotContains
            | Self::NotStartsWith
            | Self::NotEndsWith => right.iter().all(|v| self.compare_single(left, v)),
        }
    }

    fn compare_single<T: PartialEq + PartialOrd + ToString>(&self, left: &T, right: &T) -> bool {
        match self {
            Self::Equal => left == right,
            Self::NotEqual => left != right,
            Self::GreaterThan => left > right,
            Self::LowerThan => left < right,
            Self::GreaterEqual => left >= right,
            Self::LowerEqual => left <= right,
            Self::Contains => left.to_string().contains(&right.to_string()),
            Self::NotContains => !left.to_string().contains(&right.to_string()),
            Self::StartsWith => left.to_string().starts_with(&right.to_string()),
            Self::NotStartsWith => !left.to_string().starts_with(&right.to_string()),
            Self::EndsWith => left.to_string().ends_with(&right.to_string()),
            Self::NotEndsWith => !left.to_string().ends_with(&right.to_string()),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum FirewallCompareType<'a> {
    String((&'a String, &'a Vec<String>)),
    Usize((usize, &'a Vec<usize>)),
    U32((u32, &'a Vec<u32>)),
    U64((u64, &'a Vec<u64>)),
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::firewall::rules::FirewallRuleCondition;

    #[test]
    fn test_firewall_condition_compare_single() {
        assert!(FirewallRuleCondition::Equal.compare_single(&1, &1));
        assert!(!FirewallRuleCondition::Equal.compare_single(&1, &2));
        assert!(FirewallRuleCondition::NotEqual.compare_single(&1, &2));
        assert!(!FirewallRuleCondition::NotEqual.compare_single(&1, &1));
        assert!(FirewallRuleCondition::GreaterThan.compare_single(&10, &9));
        assert!(!FirewallRuleCondition::GreaterThan.compare_single(&9, &10));
        assert!(FirewallRuleCondition::GreaterThan.compare_single(&"9", &"10"));
        assert!(!FirewallRuleCondition::GreaterThan.compare_single(&"10", &"9"));
        assert!(FirewallRuleCondition::LowerThan.compare_single(&1, &2));
        assert!(!FirewallRuleCondition::LowerThan.compare_single(&2, &1));
        assert!(FirewallRuleCondition::GreaterEqual.compare_single(&2, &1));
        assert!(FirewallRuleCondition::GreaterEqual.compare_single(&1, &1));
        assert!(!FirewallRuleCondition::GreaterEqual.compare_single(&1, &2));
        assert!(FirewallRuleCondition::LowerEqual.compare_single(&1, &2));
        assert!(FirewallRuleCondition::LowerEqual.compare_single(&1, &1));
        assert!(!FirewallRuleCondition::LowerEqual.compare_single(&2, &1));
        assert!(FirewallRuleCondition::Contains.compare_single(&"Hello", &"ell"));
        assert!(!FirewallRuleCondition::Contains.compare_single(&"Hello", &"world"));
        assert!(FirewallRuleCondition::NotContains.compare_single(&"Hello", &"world"));
        assert!(!FirewallRuleCondition::NotContains.compare_single(&"Hello", &"ell"));
        assert!(FirewallRuleCondition::StartsWith.compare_single(&"Hello", &"Hel"));
        assert!(!FirewallRuleCondition::StartsWith.compare_single(&"Hello", &"lo"));
        assert!(FirewallRuleCondition::NotStartsWith.compare_single(&"Hello", &"lo"));
        assert!(!FirewallRuleCondition::NotStartsWith.compare_single(&"Hello", &"Hel"));
        assert!(FirewallRuleCondition::EndsWith.compare_single(&"Hello", &"lo"));
        assert!(!FirewallRuleCondition::EndsWith.compare_single(&"Hello", &"Hel"));
        assert!(FirewallRuleCondition::NotEndsWith.compare_single(&"Hello", &"Hel"));
        assert!(!FirewallRuleCondition::NotEndsWith.compare_single(&"Hello", &"lo"));
    }

    #[test]
    fn test_firewall_condition_compare_vec() {
        assert!(FirewallRuleCondition::Equal.compare_vec(&1, &vec![1, 2, 3]));
        assert!(!FirewallRuleCondition::Equal.compare_vec(&1, &vec![2, 3]));
        assert!(FirewallRuleCondition::NotEqual.compare_vec(&1, &vec![2, 3]));
        assert!(!FirewallRuleCondition::NotEqual.compare_vec(&1, &vec![1, 2, 3]));
        assert!(FirewallRuleCondition::GreaterThan.compare_vec(&10, &vec![9, 8, 7]));
        assert!(!FirewallRuleCondition::GreaterThan.compare_vec(&9, &vec![10, 8, 7]));
        assert!(FirewallRuleCondition::LowerThan.compare_vec(&1, &vec![2, 3, 4]));
        assert!(!FirewallRuleCondition::LowerThan.compare_vec(&2, &vec![1, 3, 4]));
        assert!(!FirewallRuleCondition::GreaterEqual.compare_vec(&2, &vec![1, 2, 3]));
        assert!(FirewallRuleCondition::GreaterEqual.compare_vec(&4, &vec![1, 2, 3]));
        assert!(FirewallRuleCondition::LowerEqual.compare_vec(&2, &vec![2, 3, 4]));
        assert!(!FirewallRuleCondition::LowerEqual.compare_vec(&2, &vec![1, 2, 3]));
        assert!(FirewallRuleCondition::Contains.compare_vec(&"Hello", &vec!["world", "ell", "lo"]));
        assert!(!FirewallRuleCondition::Contains.compare_vec(&"Hello", &vec!["world", "world"]));
        assert!(FirewallRuleCondition::NotContains.compare_vec(&"Hello", &vec!["world", "world"]));
        assert!(
            !FirewallRuleCondition::NotContains.compare_vec(&"Hello", &vec!["world", "ell", "lo"])
        );
        assert!(
            FirewallRuleCondition::StartsWith.compare_vec(&"Hello", &vec!["world", "Hel", "lo"])
        );
        assert!(!FirewallRuleCondition::StartsWith.compare_vec(&"Hello", &vec!["world", "lo"]));
        assert!(FirewallRuleCondition::NotStartsWith.compare_vec(&"Hello", &vec!["world", "lo"]));
        assert!(!FirewallRuleCondition::NotStartsWith
            .compare_vec(&"Hello", &vec!["world", "Hel", "lo"]));
        assert!(FirewallRuleCondition::EndsWith.compare_vec(&"Hello", &vec!["world", "lo", "llo"]));
        assert!(!FirewallRuleCondition::EndsWith.compare_vec(&"Hello", &vec!["world", "Hel"]));
        assert!(FirewallRuleCondition::NotEndsWith.compare_vec(&"Hello", &vec!["world", "Hel"]));
        assert!(
            !FirewallRuleCondition::NotEndsWith.compare_vec(&"Hello", &vec!["world", "lo", "llo"])
        );
    }
}
