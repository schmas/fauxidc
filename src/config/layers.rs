//! Configuration layers read from a file, an inline string, env vars or flags.

use std::path::Path;

use toml::de::{DeTable, DeValue};

use super::load::CliOverrides;
use super::types::{Config, LogFormat};
use super::{KeyPath, Layer, Source, deep_merge};
use crate::error::{ConfigError, ConfigErrors};

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

const ENV_PREFIX: &str = "FAUXIDC__";

/// Builds a layer from `FAUXIDC__` environment variables.
///
/// The rest of the name, split on `__` and lowercased, is the key path.
/// A value is parsed as a TOML value. If that fails, it stays a string.
/// Each variable is checked against [`Config`]. All errors are collected.
pub fn env_layer(vars: &[(String, String)]) -> Result<Layer, ConfigErrors> {
    let mut selected: Vec<&(String, String)> = vars
        .iter()
        .filter(|(name, _)| {
            name.get(..ENV_PREFIX.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(ENV_PREFIX))
        })
        .collect();
    selected.sort_by(|a, b| a.0.cmp(&b.0));

    let mut layer = Layer::default();
    let mut errors = Vec::new();
    for (name, value) in selected {
        match env_var_layer(name, value) {
            Ok(single) => deep_merge(&mut layer, single),
            Err(error) => errors.push(error),
        }
    }
    if errors.is_empty() {
        Ok(layer)
    } else {
        Err(ConfigErrors(errors))
    }
}

fn env_var_layer(name: &str, value: &str) -> Result<Layer, ConfigError> {
    let origin = Source::Env(name.to_owned());
    let fail = |message: String| ConfigError {
        origin: origin.clone(),
        message,
    };
    let segments: Vec<String> = name[ENV_PREFIX.len()..]
        .split("__")
        .map(str::to_lowercase)
        .collect();
    if segments.iter().any(String::is_empty) {
        return Err(fail("empty key segment in variable name".to_owned()));
    }
    let parsed = toml::from_str::<toml::Table>(&format!("v = {value}"))
        .ok()
        .and_then(|mut t| t.remove("v"))
        .unwrap_or_else(|| toml::Value::String(value.to_owned()));
    let table = segments.into_iter().rev().fold(parsed, |inner, key| {
        let mut t = toml::Table::new();
        t.insert(key, inner);
        toml::Value::Table(t)
    });
    let toml::Value::Table(table) = table else {
        return Err(fail("empty variable name".to_owned()));
    };
    toml::Value::Table(table.clone())
        .try_into::<Config>()
        .map_err(|e| fail(e.to_string()))?;
    Ok(Layer::from_table(table, origin))
}

/// Builds a layer from command-line flags.
pub fn flag_layer(f: &CliOverrides) -> Layer {
    let mut layer = Layer::default();
    let mut set = |key: &str, flag: &'static str, value: toml::Value| {
        let mut server = toml::Table::new();
        server.insert(key.to_owned(), value);
        let mut top = toml::Table::new();
        top.insert("server".to_owned(), toml::Value::Table(server));
        deep_merge(&mut layer, Layer::from_table(top, Source::Flag(flag)));
    };
    if let Some(port) = f.port {
        set("port", "--port", toml::Value::Integer(i64::from(port)));
    }
    if let Some(bind) = &f.bind {
        set("bind", "--bind", toml::Value::String(bind.clone()));
    }
    if let Some(format) = f.log_format {
        let text = match format {
            LogFormat::Text => "text",
            LogFormat::Json => "json",
        };
        set(
            "log_format",
            "--log-format",
            toml::Value::String(text.to_owned()),
        );
    }
    layer
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

    #[test]
    fn env_values_are_typed() {
        let l = env_layer(&vars(&[
            ("FAUXIDC__SERVER__PORT", "9000"),
            ("fauxidc__issuer__a__lenient", "true"),
            (
                "FAUXIDC__CLIENT__C__REDIRECT_URIS",
                r#"["http://a/*","http://b/cb"]"#,
            ),
            (
                "FAUXIDC__USER__ALICE__CLAIMS",
                r#"{ email = "alice@example.com", roles = ["admin"] }"#,
            ),
        ]))
        .unwrap();
        assert_eq!(l.table["server"]["port"].as_integer(), Some(9000));
        assert_eq!(l.table["issuer"]["a"]["lenient"].as_bool(), Some(true));
        assert_eq!(
            l.table["client"]["c"]["redirect_uris"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            l.table["user"]["alice"]["claims"]["email"].as_str(),
            Some("alice@example.com")
        );
    }

    #[test]
    fn env_url_stays_string() {
        let l = env_layer(&vars(&[(
            "FAUXIDC__ISSUER__A__ISSUER_URL",
            "http://localhost:9000/a/",
        )]))
        .unwrap();
        assert_eq!(
            l.table["issuer"]["a"]["issuer_url"].as_str(),
            Some("http://localhost:9000/a/")
        );
    }

    #[test]
    fn env_unknown_key_names_the_var() {
        let e = env_layer(&vars(&[
            ("FAUXIDC__SERVER__PROT", "1"),
            ("FAUXIDC__SERVER__PORT", "x"),
        ]))
        .unwrap_err();
        assert_eq!(e.0.len(), 2);
        assert_eq!(e.0[0].origin, Source::Env("FAUXIDC__SERVER__PORT".into()));
        assert_eq!(e.0[1].origin, Source::Env("FAUXIDC__SERVER__PROT".into()));
    }

    #[test]
    fn other_vars_are_ignored() {
        let l = env_layer(&vars(&[
            ("FAUXIDC_LOG", "debug"),
            ("FAUXIDC_CONFIG", "a.toml"),
            ("HOME", "/x"),
        ]))
        .unwrap();
        assert!(l.table.is_empty());
    }

    #[test]
    fn flags_have_flag_source() {
        let l = flag_layer(&CliOverrides {
            port: Some(9500),
            ..Default::default()
        });
        assert_eq!(l.sources[&path("server.port")], Source::Flag("--port"));
    }
}
