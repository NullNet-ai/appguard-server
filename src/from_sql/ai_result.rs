use std::str::FromStr;

use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, Type, ValueRef};

use crate::proto::aiguard::AiGuardResponse;

impl FromSql for AiGuardResponse {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value.data_type() {
            Type::Text => {
                let str = value.as_str()?;
                let v: Vec<&str> = str.splitn(2, ' ').collect();

                let confidence = f64::from_str(v.first().unwrap_or(&"0.0")).unwrap_or_default();

                let columns_str = v.get(1).unwrap_or(&"");
                let columns: Vec<String> = serde_json::from_str(columns_str).unwrap_or_default();

                Ok(AiGuardResponse {
                    confidence,
                    columns,
                })
            }
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn test_ai_guard_response_from_sql() {
        let value = ValueRef::Text("0.5 [\"a\"]".as_bytes());
        let result: AiGuardResponse = FromSql::column_result(value).unwrap();
        assert_eq!(
            result,
            AiGuardResponse {
                confidence: 0.5,
                columns: vec!["a".to_string()],
            }
        );

        let value = ValueRef::Integer(1);
        let result: Result<AiGuardResponse, _> = FromSql::column_result(value);
        assert!(result.is_err());
    }
}
