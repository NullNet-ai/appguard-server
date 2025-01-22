use rusqlite::types::ToSqlOutput;
use rusqlite::ToSql;

use crate::proto::aiguard::AiGuardResponse;

impl ToSql for AiGuardResponse {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        let reasons_str = serde_json::to_string(&self.columns).unwrap_or_default();
        let str = format!("{:.2?} {reasons_str}", self.confidence);
        Ok(ToSqlOutput::from(str))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use rusqlite::types::ToSqlOutput::Owned;
    use rusqlite::types::Value::Text;

    use super::*;

    #[test]
    fn test_ai_result_to_sql() {
        let ai_result = AiGuardResponse {
            confidence: 0.9,
            columns: vec!["a".to_string(), "b".to_string()],
        };
        let to_sql_output = ai_result.to_sql().unwrap();
        assert_eq!(to_sql_output, Owned(Text("0.90 [\"a\",\"b\"]".to_string())));
    }
}
