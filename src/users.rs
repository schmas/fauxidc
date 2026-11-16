//! Users of the config: list, get, create, replace, merge and remove.
//!
//! The Test API (`/_mock/users`) and the `fauxidc users` commands both call this module. Reads
//! use a [`Config`]. Writes return a checked [`Edit`] of the last config file
//! ([`crate::config::edit`]); the caller writes it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use toml_edit::{Item, Table};

use crate::config::edit::{self, Change, Edit, EditError, Section};
use crate::config::{Claims, Config, LoadInputs, UserConfig, UserIssuerConfig, load};

/// A User as the Test API and `fauxidc users --json` show it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserView {
    pub id: String,
    pub label: String,
    pub claims: Claims,
    /// Per-Issuer claims, by Issuer id.
    pub issuer: BTreeMap<String, UserIssuerConfig>,
}

impl UserView {
    fn new(id: &str, user: &UserConfig) -> Self {
        UserView {
            id: id.to_owned(),
            label: user.label.clone(),
            claims: user.claims.clone(),
            issuer: user.issuer.clone(),
        }
    }
}

/// The body of `POST /_mock/users`: the id and the fields of `[user.<id>]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewUser {
    pub id: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub claims: Claims,
    #[serde(default)]
    pub issuer: BTreeMap<String, UserIssuerConfig>,
}

impl NewUser {
    /// Splits the id from the User.
    pub fn into_parts(self) -> (String, UserConfig) {
        (
            self.id,
            UserConfig {
                label: self.label,
                claims: self.claims,
                issuer: self.issuer,
            },
        )
    }
}

/// All Users, by id.
pub fn list(config: &Config) -> Vec<UserView> {
    config
        .user
        .iter()
        .map(|(id, user)| UserView::new(id, user))
        .collect()
}

/// One User, or `None`.
pub fn get(config: &Config, id: &str) -> Option<UserView> {
    config.user.get(id).map(|user| UserView::new(id, user))
}

/// Adds a User to the last config file. Fails if the id exists.
pub fn create(inputs: &LoadInputs, id: &str, user: &UserConfig) -> Result<Edit, EditError> {
    edit::prepare(inputs, Section::User, id, Change::Create(to_table(user)?))
}

/// Replaces a User in the last config file.
pub fn replace(inputs: &LoadInputs, id: &str, user: &UserConfig) -> Result<Edit, EditError> {
    edit::prepare(inputs, Section::User, id, Change::Replace(to_table(user)?))
}

/// Merges a JSON Merge Patch (RFC 7396) into a User of the last config file. A `null` member
/// removes a field or a claim.
pub fn merge(inputs: &LoadInputs, id: &str, patch: &serde_json::Value) -> Result<Edit, EditError> {
    let current = load(inputs).map_err(EditError::Invalid)?;
    let Some(user) = current.config.user.get(id) else {
        if !edit::valid_id(id) {
            return Err(EditError::InvalidId(id.to_owned()));
        }
        return Err(EditError::NotFound {
            section: Section::User,
            id: id.to_owned(),
        });
    };
    let merged = merge_patch(user, patch)?;
    replace(inputs, id, &merged)
}

/// Removes a User from the last config file.
pub fn remove(inputs: &LoadInputs, id: &str) -> Result<Edit, EditError> {
    edit::prepare(inputs, Section::User, id, Change::Remove)
}

/// Applies a JSON Merge Patch (RFC 7396) to `user`.
pub fn merge_patch(user: &UserConfig, patch: &serde_json::Value) -> Result<UserConfig, EditError> {
    let mut value = serde_json::to_value(user).map_err(|e| EditError::BadInput(e.to_string()))?;
    json_merge_patch(&mut value, patch);
    serde_json::from_value(value).map_err(|e| EditError::BadInput(format!("invalid user: {e}")))
}

fn json_merge_patch(target: &mut serde_json::Value, patch: &serde_json::Value) {
    let serde_json::Value::Object(patch) = patch else {
        *target = patch.clone();
        return;
    };
    if !target.is_object() {
        *target = serde_json::Value::Object(serde_json::Map::new());
    }
    if let serde_json::Value::Object(map) = target {
        for (key, value) in patch {
            if value.is_null() {
                map.remove(key);
            } else {
                json_merge_patch(
                    map.entry(key.clone()).or_insert(serde_json::Value::Null),
                    value,
                );
            }
        }
    }
}

/// The `[user.<id>]` table of `user`: `label` and `claims` as an inline table, and one
/// `[user.<id>.issuer.<issuer-id>]` table per Issuer. Empty fields are left out.
pub fn to_table(user: &UserConfig) -> Result<Table, EditError> {
    let bad = |e: String| EditError::BadInput(e);
    let mut table = Table::new();
    if !user.label.is_empty() {
        table.insert("label", toml_edit::value(user.label.as_str()));
    }
    if !user.claims.is_empty() {
        let claims = edit::inline_table(&user.claims).map_err(|e| bad(format!("claims.{e}")))?;
        table.insert("claims", toml_edit::value(claims));
    }
    if !user.issuer.is_empty() {
        let mut issuers = Table::new();
        issuers.set_implicit(true);
        for (issuer_id, per_issuer) in &user.issuer {
            let mut t = Table::new();
            let claims = edit::inline_table(&per_issuer.claims)
                .map_err(|e| bad(format!("issuer.{issuer_id}.claims.{e}")))?;
            t.insert("claims", toml_edit::value(claims));
            issuers.insert(issuer_id, Item::Table(t));
        }
        table.insert("issuer", Item::Table(issuers));
    }
    Ok(table)
}

/// `user` as TOML text with its `[user.<id>]` header.
pub fn to_toml(id: &str, user: &UserConfig) -> Result<String, EditError> {
    let mut users = Table::new();
    users.set_implicit(true);
    users.insert(id, Item::Table(to_table(user)?));
    let mut doc = toml_edit::DocumentMut::new();
    doc.insert("user", Item::Table(users));
    Ok(doc.to_string())
}

/// Reads a User from JSON (text that starts with `{`) or TOML (the fields of `[user.<id>]`).
pub fn parse_user(text: &str) -> Result<UserConfig, EditError> {
    let bad = |e: String| EditError::BadInput(format!("invalid user: {e}"));
    if text.trim_start().starts_with('{') {
        serde_json::from_str(text).map_err(|e| bad(e.to_string()))
    } else {
        toml::from_str(text).map_err(|e| bad(e.to_string()))
    }
}

/// Reads a JSON Merge Patch from JSON (text that starts with `{`) or TOML.
pub fn parse_patch(text: &str) -> Result<serde_json::Value, EditError> {
    let bad = |e: String| EditError::BadInput(format!("invalid user: {e}"));
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

[user.alice]
label = \"Alice\"
claims = { email = \"alice@example.com\", roles = [\"admin\"] }
";

    fn file_inputs(text: &str) -> LoadInputs {
        let mut i = inputs(&[]);
        i.config_files = vec![write_tmp(text)];
        i
    }

    fn user(value: serde_json::Value) -> UserConfig {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn list_and_get_read_the_config() {
        let loaded = load(&file_inputs(BASE)).unwrap();
        let all = list(&loaded.config);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, "alice");
        assert_eq!(all[0].claims["roles"], json!(["admin"]));
        assert_eq!(get(&loaded.config, "alice").unwrap().label, "Alice");
        assert!(get(&loaded.config, "bob").is_none());
    }

    #[test]
    fn create_writes_label_claims_and_issuer_claims() {
        let i = file_inputs(BASE);
        let bob = user(json!({
            "label": "Bob",
            "claims": {"email": "bob@example.com", "age": 30},
            "issuer": {"a": {"claims": {"sub": "b-1"}}}
        }));
        let e = create(&i, "bob", &bob).unwrap();
        assert!(
            e.new_text.ends_with(
                "\n[user.bob]\nlabel = \"Bob\"\nclaims = { age = 30, email = \"bob@example.com\" }\
                 \n\n[user.bob.issuer.a]\nclaims = { sub = \"b-1\" }\n"
            ),
            "{}",
            e.new_text
        );
        assert_eq!(e.loaded.config.user["bob"], bob);
    }

    #[test]
    fn create_refuses_null_claims() {
        let i = file_inputs(BASE);
        let e = create(&i, "bob", &user(json!({"claims": {"x": null}}))).unwrap_err();
        assert!(matches!(e, EditError::BadInput(_)), "{e}");
        assert!(e.to_string().contains("claims.x"), "{e}");
    }

    #[test]
    fn merge_follows_rfc_7396() {
        let i = file_inputs(BASE);
        let e = merge(
            &i,
            "alice",
            &json!({"label": "Al", "claims": {"roles": null, "given_name": "Alice"}}),
        )
        .unwrap();
        let alice = &e.loaded.config.user["alice"];
        assert_eq!(alice.label, "Al");
        assert_eq!(
            serde_json::Value::Object(alice.claims.clone()),
            json!({"email": "alice@example.com", "given_name": "Alice"})
        );
    }

    #[test]
    fn merge_refuses_unknown_fields_and_ids() {
        let i = file_inputs(BASE);
        let e = merge(&i, "alice", &json!({"nope": 1})).unwrap_err();
        assert!(matches!(e, EditError::BadInput(_)), "{e}");
        let e = merge(&i, "zed", &json!({})).unwrap_err();
        assert!(matches!(e, EditError::NotFound { .. }), "{e}");
    }

    #[test]
    fn replace_and_remove() {
        let i = file_inputs(BASE);
        let e = replace(&i, "alice", &user(json!({"label": "A2"}))).unwrap();
        assert!(e.loaded.config.user["alice"].claims.is_empty());
        let e = remove(&i, "alice").unwrap();
        assert!(e.loaded.config.user.is_empty());
    }

    #[test]
    fn parse_user_reads_json_and_toml() {
        let from_json = parse_user(r#"{"label": "B", "claims": {"email": "b@example.com"}}"#);
        let from_toml = parse_user("label = \"B\"\nclaims = { email = \"b@example.com\" }\n");
        assert_eq!(from_json.unwrap(), from_toml.unwrap());
        assert!(parse_user("{\"bad\": 1}").is_err());
        assert_eq!(
            parse_patch("claims = { a = 1 }").unwrap(),
            json!({"claims": {"a": 1}})
        );
    }

    #[test]
    fn to_toml_has_the_header() {
        let text = to_toml("bob", &user(json!({"label": "Bob"}))).unwrap();
        assert_eq!(text, "[user.bob]\nlabel = \"Bob\"\n");
    }
}
