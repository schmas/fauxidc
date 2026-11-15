//! Claim merging and scope filtering for ID tokens, access tokens and userinfo.

use crate::config::{Claims, ClientConfig, Config, USERNAME_PLACEHOLDER};
use crate::state::Subject;

/// Claims the server owns. Configuration and login overrides can never set them.
pub const PROTOCOL_CLAIMS: &[&str] = &[
    "iss",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "nonce",
    "azp",
    "jti",
    "sid",
    "client_id",
    "scope",
];

/// Which token the claims are for. Selects the client claim set to merge.
#[derive(Clone, Copy)]
pub enum ClaimTarget {
    IdToken,
    Access,
}

/// Scope names and the claims each one grants.
const SCOPE_CLAIMS: &[(&str, &[&str])] = &[
    (
        "profile",
        &[
            "name",
            "family_name",
            "given_name",
            "middle_name",
            "nickname",
            "preferred_username",
            "profile",
            "picture",
            "website",
            "gender",
            "birthdate",
            "zoneinfo",
            "locale",
            "updated_at",
        ],
    ),
    ("email", &["email", "email_verified"]),
    ("address", &["address"]),
    ("phone", &["phone_number", "phone_number_verified"]),
];

fn merge(into: &mut Claims, from: &Claims) {
    for (k, v) in from {
        into.insert(k.clone(), v.clone());
    }
}

/// Merges claims per top-level key, later sources winning, and removes protocol claims.
///
/// Order for a configured user: issuer defaults, `sub`, user claims, per-issuer user claims,
/// client claims for `target`, login overrides. A custom subject skips the user layers.
pub fn build_claims(
    config: &Config,
    issuer_id: &str,
    client: &ClientConfig,
    subject: &Subject,
    target: ClaimTarget,
) -> Claims {
    let issuer = config.issuer.get(issuer_id);
    let mut out = Claims::new();
    if let Some(issuer) = issuer {
        merge(&mut out, &issuer.default_claims);
    }
    let client_claims = match target {
        ClaimTarget::IdToken => &client.id_claims,
        ClaimTarget::Access => &client.access_claims,
    };
    match subject {
        Subject::User { id, overrides } => {
            let sub = match issuer {
                Some(i) if !i.sub_template.is_empty() => i.sub_template.replace("{user_id}", id),
                _ => id.clone(),
            };
            out.insert("sub".into(), sub.into());
            if let Some(user) = config.user.get(id) {
                merge(&mut out, &user.claims);
                if let Some(per_issuer) = user.issuer.get(issuer_id) {
                    merge(&mut out, &per_issuer.claims);
                }
            }
            merge(&mut out, client_claims);
            merge(&mut out, overrides);
        }
        Subject::Custom { sub, claims } => {
            out.insert("sub".into(), sub.clone().into());
            merge(&mut out, client_claims);
            merge(&mut out, claims);
        }
    }
    for k in PROTOCOL_CLAIMS {
        out.remove(*k);
    }
    out
}

/// Replaces `{username}` with `username` in every string of `value`, nested arrays and
/// objects too. Object keys stay as they are.
#[must_use]
pub fn fill_username(value: &serde_json::Value, username: &str) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::String(s) => Value::String(s.replace(USERNAME_PLACEHOLDER, username)),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| fill_username(item, username))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), fill_username(v, username)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Drops claims that belong to a scope the request did not grant.
/// `sub` and claims outside every scope set are always kept.
pub fn filter_by_scope(mut claims: Claims, scopes: &[String]) -> Claims {
    for (scope, names) in SCOPE_CLAIMS {
        if !scopes.iter().any(|s| s == scope) {
            for n in *names {
                claims.remove(*n);
            }
        }
    }
    claims
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::needless_pass_by_value
)]
mod tests {
    use super::*;
    use serde_json::json;

    const STRICT_LIKE: &str = r#"[issuer.auth0]
issuer_url = "http://localhost:9000/auth0/"
sub_template = "auth0|{user_id}"
default_claims = { tenant = "t1", locale = "en" }

[client.example_app]
client_id = "example-app"
client_secret = "local"
redirect_uris = ["http://localhost:3000/api/auth/callback/*"]
id_claims = { app = "x" }

[user.alice]
label = "Alice Admin"
claims = { email = "alice@example.com", email_verified = true, given_name = "Alice", family_name = "Admin", name = "Alice Admin", roles = ["admin"] }

[user.alice.issuer.auth0]
claims = { roles = ["owner"] }

[user.bob]
label = "Bobby Viewer"
claims = { email = "bob@example.com", name = "Bobby Viewer" }
"#;

    fn cfg() -> Config {
        crate::config::load_str(STRICT_LIKE).unwrap().config
    }

    fn client() -> ClientConfig {
        cfg().client["example_app"].clone()
    }

    fn user(id: &str, overrides: serde_json::Value) -> Subject {
        Subject::User {
            id: id.into(),
            overrides: overrides.as_object().unwrap().clone(),
        }
    }

    #[test]
    fn merge_order() {
        let c = build_claims(
            &cfg(),
            "auth0",
            &client(),
            &user("alice", json!({"name": "Override"})),
            ClaimTarget::IdToken,
        );
        assert_eq!(c["sub"], "auth0|alice");
        assert_eq!(c["tenant"], "t1");
        assert_eq!(c["roles"], json!(["owner"])); // per-Issuer User claims beat User claims
        assert_eq!(c["app"], "x"); // Client id_claims
        assert_eq!(c["name"], "Override"); // Claim override beats all
    }

    #[test]
    fn explicit_sub_beats_template() {
        let mut cfg = cfg();
        cfg.user
            .get_mut("bob")
            .unwrap()
            .claims
            .insert("sub".into(), json!("00u-bob"));
        assert_eq!(
            build_claims(
                &cfg,
                "auth0",
                &client(),
                &user("bob", json!({})),
                ClaimTarget::IdToken
            )["sub"],
            "00u-bob"
        );
    }

    #[test]
    fn protocol_claims_cannot_be_overridden() {
        let c = build_claims(
            &cfg(),
            "auth0",
            &client(),
            &user(
                "alice",
                json!({"aud": "x", "iss": "y", "exp": 1, "scope": "admin"}),
            ),
            ClaimTarget::IdToken,
        );
        for k in ["aud", "iss", "exp", "scope"] {
            assert!(!c.contains_key(k), "{k}");
        }
    }

    #[test]
    fn access_target_uses_access_claims() {
        assert!(
            !build_claims(
                &cfg(),
                "auth0",
                &client(),
                &user("alice", json!({})),
                ClaimTarget::Access
            )
            .contains_key("app")
        );
    }

    #[test]
    fn custom_user() {
        let s = Subject::Custom {
            sub: "c-1".into(),
            claims: json!({"email": "carol@example.com"})
                .as_object()
                .unwrap()
                .clone(),
        };
        let c = build_claims(&cfg(), "auth0", &client(), &s, ClaimTarget::IdToken);
        assert_eq!(
            (c["sub"].as_str(), c["email"].as_str(), c["tenant"].as_str()),
            (Some("c-1"), Some("carol@example.com"), Some("t1"))
        );
    }

    #[test]
    fn scope_filter() {
        let c = json!({"sub": "s", "email": "a@example.com", "name": "A", "roles": ["r"], "locale": "en"}).as_object().unwrap().clone();
        let f = filter_by_scope(c.clone(), &["openid".into()]);
        assert_eq!(f.keys().collect::<Vec<_>>(), vec!["roles", "sub"]);
        let f = filter_by_scope(c, &["openid".into(), "email".into()]);
        assert!(f.contains_key("email") && !f.contains_key("name"));
    }

    #[test]
    fn fill_username_replaces_nested_strings() {
        let t = json!({"email":"{username}@example.test","n":1,"ok":true,"none":null,"groups":["{username}-team"],"address":{"formatted":"{username} st"},"twice":"{username}/{username}"});
        assert_eq!(
            fill_username(&t, "carol"),
            json!({"email":"carol@example.test","n":1,"ok":true,"none":null,"groups":["carol-team"],"address":{"formatted":"carol st"},"twice":"carol/carol"})
        );
    }

    #[test]
    fn fill_username_keeps_object_keys() {
        let t = json!({"{username}": "{username}"});
        assert_eq!(fill_username(&t, "carol"), json!({"{username}": "carol"}));
    }
}
