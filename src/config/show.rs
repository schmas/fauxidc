//! Renders the merged configuration with the source of each value.
//!
//! `fauxidc config` and `GET /_mock/config` use the same masking ([`masked`]) and the same
//! leaves ([`entries`]). The Clients output (`fauxidc clients`, `/_mock/clients`) masks each
//! Client with [`mask_client`].

use std::fmt::Write as _;

use super::{ClientConfig, Config, KeyPath, Loaded, Source, SourceMap};

/// Keys whose tables print as one inline table and are not walked.
const CLAIM_KEYS: [&str; 4] = ["claims", "default_claims", "id_claims", "access_claims"];

/// The text that replaces a secret value.
pub const MASK: &str = "***";

/// Private members of a JWK (RFC 7518 section 6): the key material of an RSA, EC or `oct` key.
const PRIVATE_JWK_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// One configuration leaf: its dotted key path, its masked value and its source.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub path: String,
    pub value: toml::Value,
    pub source: Source,
}

/// Renders every configuration leaf as `<path> = <value>  # <source>`.
///
/// Secrets print as `"***"` (see [`masked`]). A value with no recorded source came from a
/// default.
#[must_use]
pub fn render(loaded: &Loaded) -> String {
    let mut out = String::new();
    for e in entries(&masked(&loaded.config), &loaded.sources) {
        let _ = writeln!(out, "{} = {}  # {}", e.path, e.value, e.source);
    }
    out
}

/// The config as a TOML value with every secret replaced by `"***"`: each Client masked by
/// [`mask_client`].
#[must_use]
pub fn masked(config: &Config) -> toml::Value {
    let mut config = config.clone();
    config.client.values_mut().for_each(mask_client);
    // Config always serializes to a table. The fallback keeps this total.
    toml::Value::try_from(&config).unwrap_or_else(|_| toml::Value::Table(toml::Table::new()))
}

/// Replaces the secrets of a Client by `"***"`: its `client_secret`, and the private members
/// of a JWK in its `jwks` (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`). `fauxidc config`,
/// `fauxidc clients` and the Test API use it.
pub fn mask_client(client: &mut ClientConfig) {
    if client.client_secret.is_some() {
        client.client_secret = Some(MASK.to_owned());
    }
    if let Some(jwks) = &mut client.jwks {
        jwks.values_mut().for_each(mask_private_jwk_members);
    }
}

fn mask_private_jwk_members(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if PRIVATE_JWK_MEMBERS.contains(&key.as_str()) {
                    *child = serde_json::Value::String(MASK.to_owned());
                } else {
                    mask_private_jwk_members(child);
                }
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(mask_private_jwk_members),
        _ => {}
    }
}

/// Every leaf of `root` (from [`masked`]) with its source, in key order. A claim map is one
/// leaf. A leaf with no entry in `sources` has the source [`Source::Default`].
#[must_use]
pub fn entries(root: &toml::Value, sources: &SourceMap) -> Vec<Entry> {
    let mut out = Vec::new();
    walk(root, &mut Vec::new(), sources, &mut out);
    out
}

fn walk(value: &toml::Value, path: &mut KeyPath, sources: &SourceMap, out: &mut Vec<Entry>) {
    let toml::Value::Table(table) = value else {
        return;
    };
    for (key, child) in table {
        path.push(key.clone());
        let is_claims = CLAIM_KEYS.contains(&key.as_str());
        match child {
            toml::Value::Table(_) if !is_claims => walk(child, path, sources, out),
            _ => out.push(Entry {
                path: path.join("."),
                value: child.clone(),
                source: source_of(path, is_claims, sources),
            }),
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

    #[test]
    fn masked_hides_private_jwk_members_and_keeps_public_ones() {
        let mut config = crate::config::load_str(
            "[issuer.a]\nissuer_url = \"http://localhost:9000/a\"\n[client.app]\n",
        )
        .unwrap()
        .config;
        let jwk = serde_json::json!({"kty": "EC", "crv": "P-256", "x": "pub-x", "y": "pub-y",
            "d": "private-d", "oth": [{"r": "private-r"}]});
        let jwks = serde_json::json!({"keys": [jwk]});
        let serde_json::Value::Object(jwks) = jwks else {
            unreachable!()
        };
        let client = config.client.get_mut("app").unwrap();
        client.jwks = Some(jwks);
        client.client_secret = Some("s3cret-value".into());
        let root = masked(&config);
        let key = &root["client"]["app"]["jwks"]["keys"][0];
        assert_eq!(key["d"].as_str(), Some(MASK));
        assert_eq!(key["oth"].as_str(), Some(MASK));
        assert_eq!(key["x"].as_str(), Some("pub-x"));
        assert_eq!(root["client"]["app"]["client_secret"].as_str(), Some(MASK));
        let text = entries(&root, &SourceMap::new())
            .iter()
            .map(|e| e.value.to_string())
            .collect::<String>();
        assert!(!text.contains("private-"), "{text}");
        assert!(!text.contains("s3cret"), "{text}");
    }
}
