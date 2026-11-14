//! Semantic checks on the merged configuration.

use axum::http::Uri;

use super::types::Config;
use super::{KeyPath, Source, SourceMap};
use crate::error::{ConfigError, ConfigErrors};
use crate::issuer::issuer_path;

/// Returns `true` for an absolute `http` or `https` URI with an authority and no fragment.
fn absolute_http(uri: &str) -> Option<Uri> {
    if uri.contains('#') {
        return None;
    }
    let parsed: Uri = uri.parse().ok()?;
    (matches!(parsed.scheme_str(), Some("http" | "https")) && parsed.authority().is_some())
        .then_some(parsed)
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// `true` if `path` equals `prefix` or lies below it, matching whole segments.
fn under(path: &str, prefix: &str) -> bool {
    prefix == "/"
        || path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|r| r.starts_with('/'))
}

fn valid_redirect_uri(uri: &str) -> bool {
    let Some(parsed) = absolute_http(uri) else {
        return false;
    };
    match uri.matches('*').count() {
        0 => true,
        1 => parsed.query().is_none() && parsed.path().rsplit('/').next() == Some("*"),
        _ => false,
    }
}

fn valid_base_url(url: &str) -> bool {
    url.is_empty() || absolute_http(url).is_some_and(|u| u.query().is_none())
}

struct Collector<'a> {
    sources: &'a SourceMap,
    errors: Vec<ConfigError>,
}

impl Collector<'_> {
    /// The source of the exact key, else of any key below it, else `Default`.
    fn origin(&self, key: &[&str]) -> Source {
        let want: KeyPath = key.iter().map(|part| (*part).to_owned()).collect();
        self.sources
            .get(&want)
            .or_else(|| {
                self.sources
                    .iter()
                    .find(|(path, _)| path.starts_with(&want))
                    .map(|(_, source)| source)
            })
            .cloned()
            .unwrap_or(Source::Default)
    }

    fn push(&mut self, key: &[&str], message: String) {
        let origin = self.origin(key);
        self.errors.push(ConfigError { origin, message });
    }
}

/// Checks the merged configuration. All errors are collected.
pub fn validate(config: &Config, sources: &SourceMap) -> Result<(), ConfigErrors> {
    let mut c = Collector {
        sources,
        errors: Vec::new(),
    };

    let tables: [(&str, Vec<&String>); 3] = [
        ("issuer", config.issuer.keys().collect()),
        ("client", config.client.keys().collect()),
        ("user", config.user.keys().collect()),
    ];
    for (table, ids) in tables {
        for id in ids.into_iter().filter(|id| !valid_id(id)) {
            c.push(
                &[table, id],
                format!("invalid id \"{id}\": use a-z, 0-9 and _"),
            );
        }
    }

    check_issuers(config, &mut c);
    check_clients(config, &mut c);
    check_users(config, &mut c);

    if !valid_base_url(&config.server.public_base_url) {
        c.push(
            &["server", "public_base_url"],
            format!(
                "server.public_base_url: invalid URL \"{}\"",
                config.server.public_base_url
            ),
        );
    }

    if c.errors.is_empty() {
        Ok(())
    } else {
        Err(ConfigErrors(c.errors))
    }
}

fn check_issuers(config: &Config, c: &mut Collector<'_>) {
    if config.issuer.is_empty() {
        c.push(&["issuer"], "no issuer configured".to_owned());
    }
    let mut paths: Vec<(&str, String)> = Vec::new();
    for (id, issuer) in &config.issuer {
        if !valid_base_url(&issuer.public_base_url) {
            c.push(
                &["issuer", id, "public_base_url"],
                format!(
                    "issuer.{id}.public_base_url: invalid URL \"{}\"",
                    issuer.public_base_url
                ),
            );
        }
        if issuer.issuer_url.is_empty() {
            c.push(
                &["issuer", id, "issuer_url"],
                format!("issuer.{id}.issuer_url is required"),
            );
            continue;
        }
        match issuer_path(&issuer.issuer_url) {
            Ok(path) => {
                let reserved = RESERVED_PREFIXES
                    .iter()
                    .find(|prefix| under(&path, prefix) && **prefix != "/");
                if let Some(prefix) = reserved {
                    c.push(
                        &["issuer", id, "issuer_url"],
                        format!("issuer path {path} uses reserved prefix {prefix}"),
                    );
                }
                paths.push((id, path));
            }
            Err(reason) => c.push(
                &["issuer", id, "issuer_url"],
                format!("issuer.{id}.issuer_url: {reason}"),
            ),
        }
    }
    for (i, (id_a, a)) in paths.iter().enumerate() {
        for (id_b, b) in &paths[i + 1..] {
            if under(a, b) || under(b, a) {
                c.push(
                    &["issuer", id_b, "issuer_url"],
                    format!("issuer paths overlap: {a} ({id_a}) and {b} ({id_b})"),
                );
            }
        }
    }
}

const RESERVED_PREFIXES: [&str; 2] = ["/_mock", "/.well-known"];

fn effective_id<'a>(key: &'a str, client_id: Option<&'a String>) -> &'a str {
    client_id.map_or(key, String::as_str)
}

fn check_clients(config: &Config, c: &mut Collector<'_>) {
    for (key, client) in &config.client {
        if client.issuer != "*" && !config.issuer.contains_key(&client.issuer) {
            c.push(
                &["client", key, "issuer"],
                format!("client.{key}.issuer: unknown issuer \"{}\"", client.issuer),
            );
        }
        for uri in client
            .redirect_uris
            .iter()
            .filter(|u| !valid_redirect_uri(u))
        {
            c.push(
                &["client", key, "redirect_uris"],
                format!("client.{key}.redirect_uris: invalid \"{uri}\""),
            );
        }
    }
    let clients: Vec<_> = config.client.iter().collect();
    for (i, (key_a, a)) in clients.iter().enumerate() {
        let id = effective_id(key_a, a.client_id.as_ref());
        for (key_b, b) in &clients[i + 1..] {
            if id != effective_id(key_b, b.client_id.as_ref()) {
                continue;
            }
            let issuer = match (a.issuer.as_str(), b.issuer.as_str()) {
                ("*", other) | (other, "*") => other,
                (x, y) if x == y => x,
                _ => continue,
            };
            c.push(
                &["client", key_b],
                format!("duplicate client_id \"{id}\" for issuer {issuer}"),
            );
        }
    }
}

fn check_users(config: &Config, c: &mut Collector<'_>) {
    for (user, cfg) in &config.user {
        for issuer in cfg
            .issuer
            .keys()
            .filter(|i| !config.issuer.contains_key(*i))
        {
            c.push(
                &["user", user, "issuer", issuer],
                format!("user.{user}.issuer.{issuer}: unknown issuer"),
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::assert_is_empty)] // `errs` returns a Vec; the brief's tests assert emptiness
mod tests {
    use super::*;
    use crate::issuer::issuer_path;

    fn errs(toml: &str) -> Vec<String> {
        let c: Config = toml::from_str(toml).unwrap();
        validate(&c, &SourceMap::new())
            .err()
            .map_or_default(|e| e.0.into_iter().map(|e| e.message).collect())
    }
    const A: &str = "[issuer.a]\nissuer_url = \"http://localhost:9000/a/\"\n";

    #[test]
    fn ok_minimal() {
        assert!(errs(A).is_empty());
    }
    #[test]
    fn no_issuer() {
        assert_eq!(errs("[server]\nport = 1"), vec!["no issuer configured"]);
    }
    #[test]
    fn bad_id() {
        assert!(errs(&format!("{A}[user.Bob]\n"))[0].starts_with("invalid id \"Bob\""));
    }
    #[test]
    fn missing_url() {
        assert_eq!(
            errs("[issuer.a]\nlenient = true"),
            vec!["issuer.a.issuer_url is required"]
        );
    }
    #[test]
    fn reserved() {
        assert!(
            errs("[issuer.a]\nissuer_url = \"http://h/_mock/x\"")[0]
                .contains("reserved prefix /_mock")
        );
    }
    #[test]
    fn overlap_prefix() {
        assert!(
            errs(&format!("{A}[issuer.b]\nissuer_url = \"http://h/a/b\""))[0]
                .starts_with("issuer paths overlap")
        );
    }
    #[test]
    fn overlap_root() {
        assert!(
            errs(&format!("{A}[issuer.r]\nissuer_url = \"http://h/\""))[0]
                .starts_with("issuer paths overlap")
        );
    }
    #[test]
    fn no_overlap_similar_names() {
        assert!(errs(&format!("{A}[issuer.b]\nissuer_url = \"http://h/ab\"")).is_empty());
    }
    #[test]
    fn root_alone_ok() {
        assert!(errs("[issuer.r]\nissuer_url = \"http://h\"").is_empty());
    }
    #[test]
    fn unknown_client_issuer() {
        assert!(
            errs(&format!("{A}[client.c]\nissuer = \"zz\""))[0].contains("unknown issuer \"zz\"")
        );
    }
    #[test]
    fn duplicate_client_id() {
        assert!(
            errs(&format!(
                "{A}[client.x]\nclient_id = \"app\"\n[client.y]\nclient_id = \"app\"\nissuer = \"a\""
            ))[0]
                .starts_with("duplicate client_id \"app\"")
        );
    }
    #[test]
    fn bad_redirect_wildcard() {
        assert_eq!(
            errs(&format!(
                "{A}[client.c]\nredirect_uris = [\"http://h/*/cb\"]"
            )),
            vec!["client.c.redirect_uris: invalid \"http://h/*/cb\""]
        );
    }
    #[test]
    fn redirect_with_fragment() {
        assert_eq!(
            errs(&format!(
                "{A}[client.c]\nredirect_uris = [\"http://h/cb#x\"]"
            )),
            vec!["client.c.redirect_uris: invalid \"http://h/cb#x\""]
        );
    }
    #[test]
    fn bad_client_key() {
        assert!(errs(&format!("{A}[client.My_App]\n"))[0].starts_with("invalid id \"My_App\""));
    }
    #[test]
    fn unknown_user_issuer() {
        assert_eq!(
            errs(&format!("{A}[user.alice.issuer.zz]\n")),
            vec!["user.alice.issuer.zz: unknown issuer"]
        );
    }
    #[test]
    fn bad_public_base_url() {
        assert_eq!(
            errs(&format!("[server]\npublic_base_url = \"ftp://x\"\n{A}")),
            vec!["server.public_base_url: invalid URL \"ftp://x\""]
        );
        assert_eq!(
            errs(
                "[issuer.a]\nissuer_url = \"http://localhost:9000/a/\"\npublic_base_url = \"http://x/?q=1\"\n"
            ),
            vec!["issuer.a.public_base_url: invalid URL \"http://x/?q=1\""]
        );
    }
    #[test]
    fn good_redirect_wildcard() {
        assert!(
            errs(&format!(
                "{A}[client.c]\nredirect_uris = [\"http://localhost:3000/api/auth/callback/*\"]"
            ))
            .is_empty()
        );
    }
    #[test]
    fn issuer_path_forms() {
        assert_eq!(
            issuer_path("http://localhost:9000/auth0/").unwrap(),
            "/auth0"
        );
        assert_eq!(issuer_path("http://localhost:9000").unwrap(), "/");
        assert!(issuer_path("localhost:9000/a").is_err());
    }
}
