use rpn_predicate_interpreter::InfixExpression;
use serde::{Deserialize, Serialize};

use crate::firewall::firewall::Firewall;
use crate::firewall::rules::{FirewallExpression, FirewallRule};
use crate::proto::appguard_commands::FirewallPolicy;

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(transparent, rename_all = "snake_case")]
pub struct InfixFirewall {
    expressions: Vec<InfixFirewallExpression>,
}

impl InfixFirewall {
    pub fn into_firewall(self) -> Firewall {
        let mut firewall = Firewall::default();
        for expr in self.expressions {
            firewall.expressions.push(FirewallExpression {
                policy: expr.policy,
                expression: expr.expression.to_postfix(),
            });
        }
        firewall
    }

    pub fn is_valid(&self) -> bool {
        self.expressions
            .iter()
            .all(|expr| expr.expression.is_valid())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct InfixFirewallExpression {
    policy: FirewallPolicy,
    #[serde(flatten)]
    expression: InfixExpression<FirewallRule>,
}
