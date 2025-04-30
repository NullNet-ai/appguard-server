use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, PartialEq, Clone)]
pub struct HeaderVal(pub String, pub Vec<String>);

impl Serialize for HeaderVal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_map(Some(1))?;
        state.serialize_entry(&self.0, &self.1)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for HeaderVal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let map: HashMap<String, Vec<String>> = HashMap::deserialize(deserializer)?;
        if map.len() != 1 {
            return Err(serde::de::Error::custom("Expected a map with one entry"));
        }
        if let Some((k, v)) = map.into_iter().next() {
            Ok(HeaderVal(k, v))
        } else {
            Err(serde::de::Error::custom("Expected a non-empty map"))
        }
    }
}
