//! Configuration layers read from a file or an inline string.

use std::path::Path;

use toml::de::{DeTable, DeValue};

use super::types::Config;
use super::{KeyPath, Layer, Source};
use crate::error::ConfigError;

/// Reads a TOML file into a layer.
///
/// The file is checked against [`Config`] for unknown keys and wrong types.
/// Each leaf records the line of its key.
pub fn file_layer(path: &Path) -> Result<Layer, ConfigError> {
    let origin = |line| Source::File {
        path: path.to_path_buf(),
        line,
    };
    let fail = |message: String| ConfigError {
        origin: origin(None),
        message,
    };
    let text = std::fs::read_to_string(path).map_err(|e| fail(format!("cannot read file: {e}")))?;
    toml::from_str::<Config>(&text).map_err(|e| fail(e.to_string()))?;
    let table = toml::from_str::<toml::Table>(&text).map_err(|e| fail(e.to_string()))?;
    let spans = DeTable::parse(&text).map_err(|e| fail(e.to_string()))?;

    let mut layer = Layer::from_table(table, origin(None));
    let mut lines = Vec::new();
    collect_lines(spans.get_ref(), &text, &mut Vec::new(), &mut lines);
    for (key_path, line) in lines {
        layer.sources.insert(key_path, origin(Some(line)));
    }
    Ok(layer)
}

/// Parses an inline string into a layer.
///
/// A string that starts with `{` is JSON. Any other string is TOML.
pub fn inline_layer(text: &str) -> Result<Layer, ConfigError> {
    let fail = |message: String| ConfigError {
        origin: Source::Inline,
        message,
    };
    let table = if text.trim_start().starts_with('{') {
        serde_json::from_str::<Config>(text).map_err(|e| fail(e.to_string()))?;
        serde_json::from_str::<toml::Table>(text).map_err(|e| fail(e.to_string()))?
    } else {
        toml::from_str::<Config>(text).map_err(|e| fail(e.to_string()))?;
        toml::from_str::<toml::Table>(text).map_err(|e| fail(e.to_string()))?
    };
    Ok(Layer::from_table(table, Source::Inline))
}

fn collect_lines(
    table: &DeTable<'_>,
    text: &str,
    prefix: &mut KeyPath,
    out: &mut Vec<(KeyPath, usize)>,
) {
    for (key, value) in table {
        prefix.push(key.get_ref().as_ref().to_owned());
        match value.get_ref() {
            DeValue::Table(inner) => collect_lines(inner, text, prefix, out),
            _ => out.push((prefix.clone(), line_of(text, key.span().start))),
        }
        prefix.pop();
    }
}

fn line_of(text: &str, offset: usize) -> usize {
    text.get(..offset)
        .map_or(1, |head| head.matches('\n').count() + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Source;
    use crate::config::test_util::*;

    #[test]
    fn file_layer_records_lines() {
        let p = write_tmp(
            "[server]\nport = 9100\n\n[issuer.a]\nissuer_url = \"http://localhost:9000/a\"\n",
        );
        let l = file_layer(&p).unwrap();
        assert_eq!(
            l.sources[&path("server.port")],
            Source::File {
                path: p.clone(),
                line: Some(2)
            }
        );
        assert_eq!(
            l.sources[&path("issuer.a.issuer_url")],
            Source::File {
                path: p,
                line: Some(5)
            }
        );
    }

    #[test]
    fn file_layer_unknown_key_names_file_and_line() {
        let p = write_tmp("[issuer.a]\nlenent = true\n");
        let e = file_layer(&p).unwrap_err();
        assert!(matches!(e.origin, Source::File { .. }));
        assert!(
            e.message.contains("lenent") && e.message.contains("line 2"),
            "{}",
            e.message
        );
    }

    #[test]
    fn inline_json_and_toml() {
        assert_eq!(
            inline_layer(r#" {"server":{"port":9200}}"#).unwrap().table["server"]["port"]
                .as_integer(),
            Some(9200)
        );
        assert_eq!(
            inline_layer("[server]\nport = 9300").unwrap().table["server"]["port"].as_integer(),
            Some(9300)
        );
    }

    #[test]
    fn inline_type_error_is_reported_as_inline() {
        let e = inline_layer("[server]\nport = \"x\"").unwrap_err();
        assert_eq!(e.origin, Source::Inline);
    }

    #[test]
    fn missing_file_is_a_config_error() {
        let p = std::env::temp_dir().join("fauxidc-test-does-not-exist.toml");
        let e = file_layer(&p).unwrap_err();
        assert!(e.message.starts_with("cannot read file: "), "{}", e.message);
    }
}
