//! The JSON Schema of the config file, derived from the config structs.

use schemars::generate::SchemaSettings;

use super::Config;

/// Where the committed schema is published; also its `$id`.
pub const SCHEMA_URL: &str =
    "https://raw.githubusercontent.com/schmas/fauxidc/main/schema/fauxidc.schema.json";

/// The config JSON Schema, draft 2020-12, pretty JSON with a trailing newline.
/// `$id` = [`SCHEMA_URL`]; Issuer, Client and User maps have propertyNames `^[a-z0-9_]+$`.
#[must_use]
pub fn schema_json() -> String {
    let generator = SchemaSettings::draft2020_12().into_generator();
    let mut schema = generator.into_root_schema_for::<Config>();
    schema.insert("$id".to_owned(), SCHEMA_URL.into());
    schema.insert("title".to_owned(), "fauxidc config".into());
    let mut json = serde_json::to_string_pretty(&schema).unwrap_or_default();
    json.push('\n');
    json
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema() -> serde_json::Value {
        serde_json::from_str(&schema_json()).unwrap()
    }

    /// The definition of `name` under `$defs`.
    fn def<'a>(s: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
        &s["$defs"][name]
    }

    #[test]
    fn committed_schema_matches_the_structs() {
        let committed = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/schema/fauxidc.schema.json"
        ))
        .unwrap();
        assert_eq!(
            schema_json(),
            committed,
            "run: cargo run -- config --schema > schema/fauxidc.schema.json"
        );
    }

    #[test]
    fn schema_rejects_unknown_keys() {
        let s = schema();
        assert_eq!(s["$schema"], "https://json-schema.org/draft/2020-12/schema");
        assert_eq!(s["$id"], SCHEMA_URL);
        assert_eq!(s["additionalProperties"], false);
        for name in [
            "ServerConfig",
            "TlsConfig",
            "IssuerConfig",
            "EndpointPaths",
            "Lifetimes",
            "LifetimesOverride",
            "ClientConfig",
            "UserConfig",
            "UserIssuerConfig",
            "CustomUserConfig",
        ] {
            assert_eq!(
                def(&s, name)["additionalProperties"],
                false,
                "{name} must reject unknown keys"
            );
        }
    }

    #[test]
    fn schema_constrains_map_keys() {
        let s = schema();
        for map in ["issuer", "client", "user"] {
            assert_eq!(
                s["properties"][map]["propertyNames"]["pattern"], "^[a-z0-9_]+$",
                "{map}"
            );
        }
    }

    #[test]
    fn schema_knows_custom_user() {
        let s = schema();
        assert!(def(&s, "IssuerConfig")["properties"]["custom_user"].is_object());
    }
}
