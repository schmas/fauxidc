//! Clients of the config: list, get, create, replace, merge and remove.
//!
//! The Test API (`/_mock/clients`) and the `fauxidc clients` commands both call this module.
//! Reads use a [`Config`] and the Lenient-registered Clients of a running server. Writes return a
//! checked [`Edit`] of the last config file ([`crate::config::edit`]); the caller writes it.
//! The path and the CLI use the config key (`[client.<key>]`), not the `client_id`.

use std::collections::HashMap;

use serde::Serialize;
use toml_edit::{Item, Table};

use crate::config::edit::{self, Change, Edit, EditError, Section};
use crate::config::{ClientConfig, Config, LoadInputs, load};
use crate::users::json_merge_patch;

/// The value that replaces a `client_secret` in every read.
pub const MASKED_SECRET: &str = "***";

/// Clients that Lenient mode registered in memory, by `(Issuer id, client_id)`.
pub type LenientClients = HashMap<(String, String), ClientConfig>;

/// A Client as the Test API and `fauxidc clients --json` show it: the key, the Lenient flag and
/// the fields of `[client.<key>]` with their defaults. `client_id` is always set, and
/// `client_secret` is [`MASKED_SECRET`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ClientView {
    /// The config key. For a Lenient-registered Client: its `client_id`.
    pub key: String,
    /// `true` for a Client that Lenient mode registered in memory. It is read-only.
    pub lenient: bool,
    #[serde(flatten)]
    pub client: ClientConfig,
}

impl ClientView {
    fn new(key: &str, client: &ClientConfig, lenient: bool) -> Self {
        let mut client = client.clone();
        client.client_id.get_or_insert_with(|| key.to_owned());
        if client.client_secret.is_some() {
            client.client_secret = Some(MASKED_SECRET.to_owned());
        }
        ClientView {
            key: key.to_owned(),
            lenient,
            client,
        }
    }
}

/// The configured Clients by key, then the Lenient-registered Clients by Issuer id and
/// `client_id`.
pub fn list(config: &Config, lenient: &LenientClients) -> Vec<ClientView> {
    let mut registered: Vec<_> = lenient.iter().collect();
    registered.sort_by(|a, b| a.0.cmp(b.0));
    config
        .client
        .iter()
        .map(|(key, client)| ClientView::new(key, client, false))
        .chain(
            registered
                .into_iter()
                .map(|((_, client_id), client)| ClientView::new(client_id, client, true)),
        )
        .collect()
}

/// The configured Client `key`, else the Lenient-registered Client with the `client_id` `key`
/// (of the first Issuer id, if several Issuers registered it), else `None`.
pub fn get(config: &Config, lenient: &LenientClients, key: &str) -> Option<ClientView> {
    if let Some(client) = config.client.get(key) {
        return Some(ClientView::new(key, client, false));
    }
    lenient
        .iter()
        .filter(|((_, client_id), _)| client_id == key)
        .min_by(|a, b| a.0.cmp(b.0))
        .map(|((_, client_id), client)| ClientView::new(client_id, client, true))
}

/// Refuses a change to a Lenient-registered Client: it is not in a config file. A configured
/// Client with the same key wins, so a change to it is allowed.
pub fn check_writable(
    config: &Config,
    lenient: &LenientClients,
    key: &str,
) -> Result<(), EditError> {
    if !config.client.contains_key(key) && lenient.keys().any(|(_, client_id)| client_id == key) {
        return Err(EditError::Lenient { id: key.to_owned() });
    }
    Ok(())
}

/// Adds a Client to the last config file. Fails if the key exists.
pub fn create(inputs: &LoadInputs, key: &str, client: &ClientConfig) -> Result<Edit, EditError> {
    let table = to_table(key, client)?;
    edit::prepare(inputs, Section::Client, key, Change::Create(table))
}

/// Replaces a Client in the last config file.
pub fn replace(inputs: &LoadInputs, key: &str, client: &ClientConfig) -> Result<Edit, EditError> {
    let table = to_table(key, client)?;
    edit::prepare(inputs, Section::Client, key, Change::Replace(table))
}

/// Merges a JSON Merge Patch (RFC 7396) into a Client of the last config file. A `null` member
/// sets a field back to its default, or removes a claim.
pub fn merge(inputs: &LoadInputs, key: &str, patch: &serde_json::Value) -> Result<Edit, EditError> {
    let current = load(inputs).map_err(EditError::Invalid)?;
    let Some(client) = current.config.client.get(key) else {
        if !edit::valid_id(key) {
            return Err(EditError::InvalidId(key.to_owned()));
        }
        return Err(EditError::NotFound {
            section: Section::Client,
            id: key.to_owned(),
        });
    };
    let merged = merge_patch(client, patch)?;
    replace(inputs, key, &merged)
}

/// Removes a Client from the last config file.
pub fn remove(inputs: &LoadInputs, key: &str) -> Result<Edit, EditError> {
    edit::prepare(inputs, Section::Client, key, Change::Remove)
}

/// Applies a JSON Merge Patch (RFC 7396) to `client`.
pub fn merge_patch(
    client: &ClientConfig,
    patch: &serde_json::Value,
) -> Result<ClientConfig, EditError> {
    let mut value = serde_json::to_value(client).map_err(|e| EditError::BadInput(e.to_string()))?;
    json_merge_patch(&mut value, patch);
    serde_json::from_value(value).map_err(|e| EditError::BadInput(format!("invalid client: {e}")))
}

/// The fields of [`ClientConfig`] in the order of the struct. `to_table` writes them in this
/// order; a field that is not in the list comes last.
const FIELD_ORDER: [&str; 17] = [
    "issuer",
    "client_id",
    "client_secret",
    "redirect_uris",
    "post_logout_redirect_uris",
    "web_origins",
    "grant_types",
    "scopes",
    "audience",
    "require_pkce",
    "rotate_refresh_tokens",
    "refresh_reuse_leeway_secs",
    "id_claims",
    "access_claims",
    "lifetimes",
    "jwks",
    "jwks_uri",
];

/// The `[client.<key>]` table of `client`. Only fields that differ from the default are written,
/// and `client_id` only when it differs from `key`. Maps are inline tables.
pub fn to_table(key: &str, client: &ClientConfig) -> Result<Table, EditError> {
    let bad = |e: String| EditError::BadInput(e);
    let to_json = |c: &ClientConfig| serde_json::to_value(c).map_err(|e| bad(e.to_string()));
    let serde_json::Value::Object(mut fields) = to_json(client)? else {
        return Err(bad("a Client must be an object".to_owned()));
    };
    let defaults = to_json(&ClientConfig::default())?;
    let mut names: Vec<String> = fields.keys().cloned().collect();
    names.sort_by_key(|name| {
        FIELD_ORDER
            .iter()
            .position(|known| known == name)
            .unwrap_or(FIELD_ORDER.len())
    });
    let mut table = Table::new();
    for name in names {
        let Some(mut value) = fields.remove(&name) else {
            continue;
        };
        if value.is_null() || defaults.get(&name) == Some(&value) {
            continue;
        }
        if name == "client_id" && value.as_str() == Some(key) {
            continue;
        }
        if name == "lifetimes"
            && let serde_json::Value::Object(lifetimes) = &mut value
        {
            lifetimes.retain(|_, v| !v.is_null());
        }
        let value = match &value {
            serde_json::Value::Object(map) => edit::inline_table(map)
                .map(toml_edit::Value::InlineTable)
                .map_err(|e| bad(format!("{name}.{e}")))?,
            other => edit::toml_value(other).map_err(|e| bad(format!("{name}: {e}")))?,
        };
        table.insert(&name, toml_edit::value(value));
    }
    Ok(table)
}

/// `client` as TOML text with its `[client.<key>]` header. Masks nothing: the caller masks.
pub fn to_toml(key: &str, client: &ClientConfig) -> Result<String, EditError> {
    let mut clients = Table::new();
    clients.set_implicit(true);
    clients.insert(key, Item::Table(to_table(key, client)?));
    let mut doc = toml_edit::DocumentMut::new();
    doc.insert("client", Item::Table(clients));
    Ok(doc.to_string())
}

/// The key and the Client of a `POST /_mock/clients` body: `key` and the fields of
/// `[client.<key>]`.
pub fn split_new(body: serde_json::Value) -> Result<(String, ClientConfig), EditError> {
    let bad = |e: String| EditError::BadInput(format!("invalid client: {e}"));
    let serde_json::Value::Object(mut fields) = body else {
        return Err(bad("the body must be a JSON object".to_owned()));
    };
    let key = match fields.remove("key") {
        Some(serde_json::Value::String(key)) => key,
        Some(_) => return Err(bad("`key` must be a string".to_owned())),
        None => return Err(bad("missing field `key`".to_owned())),
    };
    let client = serde_json::from_value(serde_json::Value::Object(fields))
        .map_err(|e| bad(e.to_string()))?;
    Ok((key, client))
}

/// Reads a Client from JSON (text that starts with `{`) or TOML (the fields of
/// `[client.<key>]`).
pub fn parse_client(text: &str) -> Result<ClientConfig, EditError> {
    let bad = |e: String| EditError::BadInput(format!("invalid client: {e}"));
    if text.trim_start().starts_with('{') {
        serde_json::from_str(text).map_err(|e| bad(e.to_string()))
    } else {
        toml::from_str(text).map_err(|e| bad(e.to_string()))
    }
}

/// Reads a JSON Merge Patch from JSON (text that starts with `{`) or TOML.
pub fn parse_patch(text: &str) -> Result<serde_json::Value, EditError> {
    let bad = |e: String| EditError::BadInput(format!("invalid client: {e}"));
    if text.trim_start().starts_with('{') {
        serde_json::from_str(text).map_err(|e| bad(e.to_string()))
    } else {
        let table: toml::Table = toml::from_str(text).map_err(|e| bad(e.to_string()))?;
        serde_json::to_value(table).map_err(|e| bad(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_util::*;
    use serde_json::json;

    const BASE: &str = "\
[issuer.a]
issuer_url = \"http://localhost:9000/a\"

# The web app.
[client.web]
client_id = \"web-app\"
client_secret = \"local\"
redirect_uris = [\"http://localhost:3000/cb\"]
";

    fn file_inputs(text: &str) -> LoadInputs {
        let mut i = inputs(&[]);
        i.config_files = vec![write_tmp(text)];
        i
    }

    fn client(value: serde_json::Value) -> ClientConfig {
        serde_json::from_value(value).unwrap()
    }

    fn lenient_app() -> LenientClients {
        let registered = ClientConfig {
            issuer: "a".to_owned(),
            client_id: Some("new-app".to_owned()),
            redirect_uris: vec!["http://localhost:4000/cb".to_owned()],
            ..ClientConfig::default()
        };
        HashMap::from([(("a".to_owned(), "new-app".to_owned()), registered)])
    }

    #[test]
    fn list_and_get_mask_the_secret_and_set_the_client_id() {
        let loaded = load(&file_inputs(BASE)).unwrap();
        let all = list(&loaded.config, &lenient_app());
        assert_eq!(all.len(), 2);
        let web = &all[0];
        assert_eq!((web.key.as_str(), web.lenient), ("web", false));
        assert_eq!(web.client.client_id.as_deref(), Some("web-app"));
        assert_eq!(web.client.client_secret.as_deref(), Some(MASKED_SECRET));
        let registered = &all[1];
        assert_eq!(
            (registered.key.as_str(), registered.lenient),
            ("new-app", true)
        );
        assert_eq!(registered.client.issuer, "a");

        let json = serde_json::to_value(web).unwrap();
        assert_eq!(json["key"], "web");
        assert_eq!(json["client_secret"], "***");
        assert_eq!(
            json["grant_types"],
            json!(["authorization_code", "refresh_token"])
        );

        let none = LenientClients::new();
        assert_eq!(get(&loaded.config, &none, "web").unwrap().key, "web");
        assert!(
            get(&loaded.config, &none, "web-app").is_none(),
            "the path uses the key"
        );
        assert!(
            get(&loaded.config, &lenient_app(), "new-app")
                .unwrap()
                .lenient
        );
    }

    #[test]
    fn a_lenient_client_is_read_only() {
        let loaded = load(&file_inputs(BASE)).unwrap();
        let e = check_writable(&loaded.config, &lenient_app(), "new-app").unwrap_err();
        assert!(matches!(e, EditError::Lenient { .. }), "{e}");
        assert!(check_writable(&loaded.config, &lenient_app(), "web").is_ok());
        assert!(check_writable(&loaded.config, &lenient_app(), "other").is_ok());
    }

    #[test]
    fn create_writes_only_the_fields_that_differ_from_the_default() {
        let i = file_inputs(BASE);
        let svc = client(json!({
            "client_secret": "s",
            "grant_types": ["client_credentials"],
            "scopes": ["openid", "profile", "email", "offline_access"],
            "access_claims": {"tier": "gold"},
            "lifetimes": {"access_token": 60}
        }));
        let e = create(&i, "svc", &svc).unwrap();
        assert!(
            e.new_text.ends_with(
                "\n[client.svc]\nclient_secret = \"s\"\ngrant_types = [\"client_credentials\"]\n\
                 access_claims = { tier = \"gold\" }\nlifetimes = { access_token = 60 }\n"
            ),
            "{}",
            e.new_text
        );
        assert_eq!(e.loaded.config.client["svc"], svc);
    }

    #[test]
    fn to_table_keeps_a_client_id_that_differs_from_the_key() {
        let c = client(json!({"client_id": "svc", "audience": "https://api.example.test"}));
        assert_eq!(
            to_toml("svc", &c).unwrap(),
            "[client.svc]\naudience = \"https://api.example.test\"\n"
        );
        assert_eq!(
            to_toml("svc2", &c).unwrap(),
            "[client.svc2]\nclient_id = \"svc\"\naudience = \"https://api.example.test\"\n"
        );
    }

    #[test]
    fn field_order_has_every_field() {
        let c = ClientConfig {
            jwks: Some(serde_json::Map::new()),
            ..ClientConfig::default()
        };
        let json = serde_json::to_value(c).unwrap();
        for name in json.as_object().unwrap().keys() {
            assert!(FIELD_ORDER.contains(&name.as_str()), "{name}");
        }
    }

    #[test]
    fn create_refuses_null_claims_and_invalid_config() {
        let i = file_inputs(BASE);
        let e = create(&i, "svc", &client(json!({"id_claims": {"x": null}}))).unwrap_err();
        assert!(matches!(e, EditError::BadInput(_)), "{e}");
        assert!(e.to_string().contains("id_claims.x"), "{e}");
        let e = create(&i, "svc", &client(json!({"issuer": "nope"}))).unwrap_err();
        assert!(matches!(e, EditError::Invalid(_)), "{e}");
        let e = create(&i, "web", &ClientConfig::default()).unwrap_err();
        assert!(matches!(e, EditError::Exists { .. }), "{e}");
    }

    #[test]
    fn merge_follows_rfc_7396_and_keeps_the_secret() {
        let i = file_inputs(BASE);
        let e = merge(
            &i,
            "web",
            &json!({"redirect_uris": ["http://localhost:3001/cb"], "client_id": null}),
        )
        .unwrap();
        let web = &e.loaded.config.client["web"];
        assert_eq!(web.redirect_uris, ["http://localhost:3001/cb"]);
        assert_eq!(web.client_secret.as_deref(), Some("local"));
        assert_eq!(web.client_id, None, "null sets the default");
        assert!(
            e.new_text.contains("# The web app.\n[client.web]\n"),
            "{}",
            e.new_text
        );
    }

    #[test]
    fn merge_refuses_unknown_fields_and_keys() {
        let i = file_inputs(BASE);
        let e = merge(&i, "web", &json!({"nope": 1})).unwrap_err();
        assert!(matches!(e, EditError::BadInput(_)), "{e}");
        let e = merge(&i, "zed", &json!({})).unwrap_err();
        assert!(matches!(e, EditError::NotFound { .. }), "{e}");
        assert_eq!(e.to_string(), "unknown client: zed");
    }

    #[test]
    fn replace_and_remove() {
        let i = file_inputs(BASE);
        let e = replace(&i, "web", &client(json!({"require_pkce": true}))).unwrap();
        let web = &e.loaded.config.client["web"];
        assert!(web.require_pkce && web.client_secret.is_none());
        let e = remove(&i, "web").unwrap();
        assert!(e.loaded.config.client.is_empty());
    }

    #[test]
    fn split_new_takes_the_key() {
        let (key, c) = split_new(json!({"key": "svc", "client_secret": "s"})).unwrap();
        assert_eq!(key, "svc");
        assert_eq!(c.client_secret.as_deref(), Some("s"));
        for bad in [
            json!({"client_secret": "s"}),
            json!({"key": 1}),
            json!({"key": "x", "nope": 1}),
            json!([]),
        ] {
            assert!(split_new(bad.clone()).is_err(), "{bad}");
        }
    }

    #[test]
    fn parse_client_reads_json_and_toml() {
        let from_json = parse_client(r#"{"redirect_uris": ["http://localhost:1/cb"]}"#);
        let from_toml = parse_client("redirect_uris = [\"http://localhost:1/cb\"]\n");
        assert_eq!(from_json.unwrap(), from_toml.unwrap());
        assert!(parse_client("{\"bad\": 1}").is_err());
        assert_eq!(
            parse_patch("lifetimes = { code = 5 }").unwrap(),
            json!({"lifetimes": {"code": 5}})
        );
    }
}
