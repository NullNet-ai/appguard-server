use rpn_predicate_interpreter::PredicateEvaluator;
use serde::{Deserialize, Serialize};

use crate::firewall::rules::{FirewallCompareType, FirewallRuleField, FirewallRuleWithDirection};
use crate::proto::appguard::AppGuardIpInfo;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum IpInfoField {
    Country(Vec<String>),
    Asn(Vec<String>),
    Org(Vec<String>),
    Continent(Vec<String>),
    City(Vec<String>),
    Region(Vec<String>),
    Postal(Vec<String>),
    Timezone(Vec<String>),
}

impl IpInfoField {
    pub fn get_field_name(&self) -> &str {
        match self {
            IpInfoField::Country(_) => "country",
            IpInfoField::Asn(_) => "asn",
            IpInfoField::Org(_) => "org",
            IpInfoField::Continent(_) => "continent",
            IpInfoField::City(_) => "city",
            IpInfoField::Region(_) => "region",
            IpInfoField::Postal(_) => "postal",
            IpInfoField::Timezone(_) => "timezone",
        }
    }

    fn get_compare_fields<'a>(
        &'a self,
        item: &'a AppGuardIpInfo,
    ) -> Option<FirewallCompareType<'a>> {
        match self {
            IpInfoField::Country(v) => item
                .country
                .as_ref()
                .map(|country| FirewallCompareType::String((country, v))),
            IpInfoField::Asn(v) => item
                .asn
                .as_ref()
                .map(|asn| FirewallCompareType::String((asn, v))),
            IpInfoField::Org(v) => item
                .org
                .as_ref()
                .map(|org| FirewallCompareType::String((org, v))),
            IpInfoField::Continent(v) => item
                .continent_code
                .as_ref()
                .map(|continent| FirewallCompareType::String((continent, v))),
            IpInfoField::City(v) => item
                .city
                .as_ref()
                .map(|city| FirewallCompareType::String((city, v))),
            IpInfoField::Region(v) => item
                .region
                .as_ref()
                .map(|region| FirewallCompareType::String((region, v))),
            IpInfoField::Postal(v) => item
                .postal
                .as_ref()
                .map(|postal| FirewallCompareType::String((postal, v))),
            IpInfoField::Timezone(v) => item
                .timezone
                .as_ref()
                .map(|timezone| FirewallCompareType::String((timezone, v))),
        }
    }
}

impl<'a> PredicateEvaluator for &'a AppGuardIpInfo {
    type Predicate = FirewallRuleWithDirection<'a>;
    type Reason = String;

    fn evaluate_predicate(&self, predicate: &Self::Predicate) -> bool {
        if let FirewallRuleField::IpInfo(f) = &predicate.rule.field {
            return predicate.rule.condition.compare(f.get_compare_fields(self));
        }
        false
    }

    fn get_reason(&self, predicate: &Self::Predicate) -> Self::Reason {
        predicate.rule.field.get_field_name()
    }

    fn is_blacklisted(&self) -> bool {
        self.blacklist
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn sample_ip_info() -> AppGuardIpInfo {
        AppGuardIpInfo {
            country: Some("IT".to_string()),
            asn: Some("AS1234".to_string()),
            org: Some("Example".to_string()),
            continent_code: Some("EU".to_string()),
            city: Some("Rome".to_string()),
            region: Some("Lazio".to_string()),
            postal: Some("00100".to_string()),
            timezone: Some("Europe/Rome".to_string()),
            blacklist: true,
            ..Default::default()
        }
    }

    #[test]
    fn test_ip_info_get_country() {
        let ip_info = sample_ip_info();
        let ip_info_field = IpInfoField::Country(vec!["US".to_string()]);
        assert_eq!(
            ip_info_field.get_compare_fields(&ip_info),
            Some(FirewallCompareType::String((
                &"IT".to_string(),
                &vec!["US".to_string()]
            )))
        );
    }

    #[test]
    fn test_ip_info_get_asn() {
        let ip_info = sample_ip_info();
        let ip_info_field = IpInfoField::Asn(vec!["wow".to_string()]);
        assert_eq!(
            ip_info_field.get_compare_fields(&ip_info),
            Some(FirewallCompareType::String((
                &"AS1234".to_string(),
                &vec!["wow".to_string()]
            )))
        );
    }

    #[test]
    fn test_ip_info_get_org() {
        let ip_info = sample_ip_info();
        let ip_info_field = IpInfoField::Org(vec!["my_org_99".to_string(), "2nd org".to_string()]);
        assert_eq!(
            ip_info_field.get_compare_fields(&ip_info),
            Some(FirewallCompareType::String((
                &"Example".to_string(),
                &vec!["my_org_99".to_string(), "2nd org".to_string()]
            )))
        );
    }

    #[test]
    fn test_ip_info_get_continent() {
        let ip_info = sample_ip_info();
        let ip_info_field = IpInfoField::Continent(vec!["NA".to_string()]);
        assert_eq!(
            ip_info_field.get_compare_fields(&ip_info),
            Some(FirewallCompareType::String((
                &"EU".to_string(),
                &vec!["NA".to_string()]
            )))
        );
    }

    #[test]
    fn test_ip_info_get_city() {
        let ip_info = sample_ip_info();
        let ip_info_field = IpInfoField::City(vec!["New York".to_string()]);
        assert_eq!(
            ip_info_field.get_compare_fields(&ip_info),
            Some(FirewallCompareType::String((
                &"Rome".to_string(),
                &vec!["New York".to_string()]
            )))
        );
    }

    #[test]
    fn test_ip_info_get_region() {
        let ip_info = sample_ip_info();
        let ip_info_field = IpInfoField::Region(vec!["California".to_string()]);
        assert_eq!(
            ip_info_field.get_compare_fields(&ip_info),
            Some(FirewallCompareType::String((
                &"Lazio".to_string(),
                &vec!["California".to_string()]
            )))
        );
    }

    #[test]
    fn test_ip_info_get_postal() {
        let ip_info = sample_ip_info();
        let ip_info_field = IpInfoField::Postal(vec!["123456".to_string()]);
        assert_eq!(
            ip_info_field.get_compare_fields(&ip_info),
            Some(FirewallCompareType::String((
                &"00100".to_string(),
                &vec!["123456".to_string()]
            )))
        );
    }

    #[test]
    fn test_ip_info_get_timezone() {
        let ip_info = sample_ip_info();
        let ip_info_field = IpInfoField::Timezone(vec!["US central".to_string()]);
        assert_eq!(
            ip_info_field.get_compare_fields(&ip_info),
            Some(FirewallCompareType::String((
                &"Europe/Rome".to_string(),
                &vec!["US central".to_string()]
            )))
        );
    }
}
