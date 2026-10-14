use std::fmt;

use serde::de::DeserializeSeed;

use serde::de::Deserializer;

use serde::de::MapAccess;

use serde::de::Visitor;

use serde_json::Map;

use serde_json::Value;

/// Reads a JSON object into a `Map` and records the member names that repeat.
///
/// `serde_json::Map` keeps the last value of a repeated name without saying so, hence this
/// visitor. It is a seed and not a `Deserialize` because it needs somewhere to leave the
/// names it found: serde errors can't carry them. Names are compared once decoded, so `"a"`
/// and `"a"` are the same name, and case-sensitive, with no normalization.
///
/// Only the top level is checked, not the objects nested inside the values.
pub(super) struct StrictMap<'a> {
    pub duplicates: &'a mut Vec<String>,
}

impl<'de> Visitor<'de> for StrictMap<'_> {
    type Value = Map<String, Value>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        let mut map = Map::new();

        // It keeps reading after a repeated name: whether the rest is valid JSON is decided
        // by the caller, and an error in it has to win over the duplicates.
        while let Some((name, value)) = access.next_entry::<String, Value>()? {
            if map.insert(name.clone(), value).is_some() && !self.duplicates.contains(&name) {
                self.duplicates.push(name);
            }
        }

        Ok(map)
    }
}

impl<'de> DeserializeSeed<'de> for StrictMap<'_> {
    type Value = Map<String, Value>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_map(self)
    }
}
