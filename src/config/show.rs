//! Renders the merged configuration with the source of each value.

use std::fmt::Write as _;

use super::{KeyPath, Loaded, Source, SourceMap};

/// Keys whose tables print as one inline table and are not walked.
const CLAIM_KEYS: [&str; 4] = ["claims", "default_claims", "id_claims", "access_claims"];

/// Renders every configuration leaf as `<path> = <value>  # <source>`.
///
/// Values of `client_secret` print as `"***"`. A value with no recorded
/// source came from a default.
#[must_use]
pub fn render(loaded: &Loaded) -> String {
    // Config always serializes to a table. The fallback keeps this total.
    let root = toml::Value::try_from(&loaded.config)
        .unwrap_or_else(|_| toml::Value::Table(toml::Table::new()));
    let mut out = String::new();
    walk(&root, &mut Vec::new(), &loaded.sources, &mut out);
    out
}

fn walk(value: &toml::Value, path: &mut KeyPath, sources: &SourceMap, out: &mut String) {
    let toml::Value::Table(table) = value else {
        return;
    };
    for (key, child) in table {
        path.push(key.clone());
        let is_claims = CLAIM_KEYS.contains(&key.as_str());
        match child {
            toml::Value::Table(_) if !is_claims => walk(child, path, sources, out),
            _ => {
                let shown = if key == "client_secret" {
                    "\"***\"".to_owned()
                } else {
                    child.to_string()
                };
                let source = source_of(path, is_claims, sources);
                let _ = writeln!(out, "{} = {shown}  # {source}", path.join("."));
            }
        }
        path.pop();
    }
}

/// Returns the source of a leaf, or of the first leaf under a claim map.
fn source_of(path: &KeyPath, is_claims: bool, sources: &SourceMap) -> Source {
    let found = if is_claims {
        sources
            .iter()
            .find(|(k, _)| k.starts_with(path.as_slice()))
            .map(|(_, s)| s)
    } else {
        sources.get(path)
    };
    found.cloned().unwrap_or(Source::Default)
}

#[cfg(test)]
mod tests {
    use super::super::test_util::{inputs, write_tmp};
    use super::*;
    use crate::config::load;

    #[test]
    fn render_shows_sources_and_masks_secrets() {
        let f = write_tmp(
            "[issuer.a]\nissuer_url = \"http://localhost:9000/a\"\n[client.app]\nclient_secret = \"local\"\n",
        );
        let mut i = inputs(&[("FAUXIDC__SERVER__PORT", "9100")]);
        i.config_files = vec![f.clone()];
        let out = render(&load(&i).unwrap());
        assert!(
            out.contains("server.port = 9100  # env FAUXIDC__SERVER__PORT"),
            "{out}"
        );
        assert!(
            out.contains(&format!(
                "issuer.a.issuer_url = \"http://localhost:9000/a\"  # {}:2",
                f.display()
            )),
            "{out}"
        );
        assert!(out.contains("client.app.client_secret = \"***\""), "{out}");
        assert!(!out.contains("local\""), "{out}");
        assert!(
            out.contains("server.bind = \"127.0.0.1\"  # default"),
            "{out}"
        );
    }

    #[test]
    fn render_prints_claim_maps_inline_with_leaf_source() {
        let f = write_tmp(
            "[issuer.a]\nissuer_url = \"http://localhost:9000/a\"\n[user.alice]\nclaims = { email = \"alice@example.com\" }\n",
        );
        let mut i = inputs(&[]);
        i.config_files = vec![f.clone()];
        let out = render(&load(&i).unwrap());
        assert!(
            out.contains(&format!(
                "user.alice.claims = {{ email = \"alice@example.com\" }}  # {}:4",
                f.display()
            )),
            "{out}"
        );
    }
}
