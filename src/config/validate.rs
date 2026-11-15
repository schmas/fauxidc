//! Semantic checks on the merged configuration.

use axum::http::Uri;

use super::types::{ClientConfig, Config, EndpointPaths, SigningAlg};
use super::{KeyPath, Source, SourceMap};
use crate::authorize::CUSTOM_USER;
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
    check_key_files(config, &mut c);
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
        if id == RESERVED_ISSUER_ID {
            c.push(
                &["issuer", id],
                format!(
                    "issuer id \"{RESERVED_ISSUER_ID}\" is reserved: it would shadow /_mock/static/*"
                ),
            );
        }
        if !valid_base_url(&issuer.public_base_url) {
            c.push(
                &["issuer", id, "public_base_url"],
                format!(
                    "issuer.{id}.public_base_url: invalid URL \"{}\"",
                    issuer.public_base_url
                ),
            );
        }
        check_endpoint_paths(id, &issuer.paths, c);
        check_logout_aliases(id, &issuer.logout_param_aliases, c);
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

/// One key file holds one key: a `key_file` shared by the server and Issuers, or by several
/// Issuers, needs the same `signing_alg` for all of them. The server key is RS256.
fn check_key_files(config: &Config, c: &mut Collector<'_>) {
    let mut entries: Vec<(&str, String, SigningAlg)> = vec![(
        config.server.key_file.as_str(),
        "server.key_file".to_owned(),
        SigningAlg::RS256,
    )];
    for (id, issuer) in &config.issuer {
        entries.push((
            issuer.key_file.as_str(),
            format!("issuer.{id}.key_file"),
            issuer.signing_alg,
        ));
    }
    entries.retain(|(file, _, _)| !file.is_empty());
    let mut files: Vec<&str> = entries.iter().map(|(file, _, _)| *file).collect();
    files.sort_unstable();
    files.dedup();
    for file in files {
        let group: Vec<&(&str, String, SigningAlg)> =
            entries.iter().filter(|(f, _, _)| *f == file).collect();
        if group.iter().all(|(_, _, alg)| *alg == group[0].2) {
            continue;
        }
        let names: Vec<&str> = group.iter().map(|(_, key, _)| key.as_str()).collect();
        let last: Vec<&str> = names
            .last()
            .copied()
            .unwrap_or_default()
            .split('.')
            .collect();
        c.push(
            &last,
            format!(
                "{} use the same key file \"{file}\" with different signing_alg values; one file holds one key",
                names.join(" and ")
            ),
        );
    }
}

fn valid_endpoint_path(path: &str) -> Result<(), &'static str> {
    if !path.starts_with('/') {
        return Err("must start with /");
    }
    if path == "/" {
        return Err("must not be /");
    }
    if path.contains(['?', '#']) {
        return Err("must not contain ? or #");
    }
    if path.contains(['{', '}', '*']) {
        return Err("must not contain {, } or *");
    }
    if path.contains("//") {
        return Err("must not contain an empty segment");
    }
    if under(path, "/.well-known") {
        return Err("must not be under /.well-known");
    }
    if under(path, "/_mock") {
        return Err("must not be under /_mock");
    }
    if path
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return Err("must not contain a . or .. segment");
    }
    if !path
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || "/-._~:@!$&'()+,;=".contains(ch))
    {
        return Err("must use only URL path characters (no spaces, %, \\ or non-ASCII)");
    }
    Ok(())
}

fn check_endpoint_paths(id: &str, paths: &EndpointPaths, c: &mut Collector<'_>) {
    let all = paths.all();
    for (e, path) in all {
        let key = e.key();
        if let Err(reason) = valid_endpoint_path(path) {
            c.push(
                &["issuer", id, "paths", key],
                format!("issuer.{id}.paths.{key}: \"{path}\" {reason}"),
            );
        }
    }
    for (i, (ea, a)) in all.iter().enumerate() {
        for (eb, b) in &all[i + 1..] {
            if a.trim_end_matches('/') == b.trim_end_matches('/') {
                c.push(
                    // The parent key falls back to the source of any key below it.
                    &["issuer", id, "paths"],
                    format!(
                        "issuer.{id}.paths: {} and {} both use {}",
                        ea.key(),
                        eb.key(),
                        a.trim_end_matches('/')
                    ),
                );
            }
        }
    }
}

/// Parameters of RP-Initiated Logout 1.0 section 2 that an alias may map to.
const LOGOUT_PARAMS: [&str; 6] = [
    "id_token_hint",
    "logout_hint",
    "client_id",
    "post_logout_redirect_uri",
    "state",
    "ui_locales",
];

fn check_logout_aliases(
    id: &str,
    aliases: &std::collections::BTreeMap<String, String>,
    c: &mut Collector<'_>,
) {
    for (alias, target) in aliases {
        let at = ["issuer", id, "logout_param_aliases"];
        if alias.is_empty() {
            c.push(
                &at,
                format!("issuer.{id}.logout_param_aliases: empty alias name"),
            );
        } else if alias == target {
            c.push(
                &at,
                format!("issuer.{id}.logout_param_aliases.{alias}: alias equals its target"),
            );
        }
        if !LOGOUT_PARAMS.contains(&target.as_str()) {
            c.push(
                &at,
                format!(
                    "issuer.{id}.logout_param_aliases.{alias}: \"{target}\" is not a logout parameter (use one of {})",
                    LOGOUT_PARAMS.join(", ")
                ),
            );
        }
    }
}

/// `true` for `http(s)://host[:port]` with an empty path (one trailing `/` allowed).
fn valid_origin(origin: &str) -> bool {
    let bare = origin.strip_suffix('/').unwrap_or(origin);
    absolute_http(bare).is_some_and(|u| {
        u.query().is_none()
            && bare
                .split_once("://")
                .is_some_and(|(_, rest)| !rest.contains('/'))
    })
}

const GRANT_TYPES: [&str; 3] = ["authorization_code", "refresh_token", "client_credentials"];

/// An Issuer id that would shadow `/_mock/static/{*path}` in the Test API route.
const RESERVED_ISSUER_ID: &str = "static";

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
        for uri in client
            .post_logout_redirect_uris
            .iter()
            .filter(|u| !valid_redirect_uri(u))
        {
            c.push(
                &["client", key, "post_logout_redirect_uris"],
                format!("client.{key}.post_logout_redirect_uris: invalid \"{uri}\""),
            );
        }
        for origin in client
            .web_origins
            .iter()
            .flatten()
            .filter(|o| !valid_origin(o))
        {
            c.push(
                &["client", key, "web_origins"],
                format!("client.{key}.web_origins: invalid origin \"{origin}\""),
            );
        }
        for grant in client
            .grant_types
            .iter()
            .filter(|g| !GRANT_TYPES.contains(&g.as_str()))
        {
            c.push(
                &["client", key, "grant_types"],
                format!(
                    "client.{key}.grant_types: unknown grant type \"{grant}\" (use one of {})",
                    GRANT_TYPES.join(", ")
                ),
            );
        }
    }
    for (key, client) in &config.client {
        check_client_keys(key, client, c);
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

/// Checks the `private_key_jwt` keys of a Client: `jwks` is a JWK set of RSA or EC P-256
/// keys, `jwks_uri` is an absolute `http://` URL, and not both.
fn check_client_keys(key: &str, client: &ClientConfig, c: &mut Collector<'_>) {
    if let Some(jwks) = &client.jwks {
        if let Err(e) = crate::client_auth::parse_jwks(jwks) {
            c.push(&["client", key, "jwks"], format!("client.{key}.jwks: {e}"));
        }
        if !client.jwks_uri.is_empty() {
            c.push(
                &["client", key, "jwks_uri"],
                format!("client.{key}: set jwks or jwks_uri, not both"),
            );
        }
    }
    let uri = &client.jwks_uri;
    if uri.is_empty() {
        return;
    }
    let message = match absolute_http(uri) {
        Some(u) if u.scheme_str() == Some("http") => return,
        Some(_) => format!(
            "client.{key}.jwks_uri: https is not supported, use an http:// URL or an inline jwks (\"{uri}\")"
        ),
        None => format!("client.{key}.jwks_uri: must be an absolute http:// URL (\"{uri}\")"),
    };
    c.push(&["client", key, "jwks_uri"], message);
}

fn check_users(config: &Config, c: &mut Collector<'_>) {
    for (user, cfg) in &config.user {
        if user == CUSTOM_USER {
            c.push(
                &["user", user],
                format!(
                    "user id \"{CUSTOM_USER}\" is reserved for the Custom user on the login page"
                ),
            );
        }
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
    fn unknown_signing_alg_names_the_key() {
        let err = crate::config::load_str(&format!("{A}signing_alg = \"HS256\"\n"))
            .err()
            .unwrap()
            .to_string();
        assert!(
            err.contains("signing_alg") && err.contains("HS256"),
            "{err}"
        );
    }
    #[test]
    fn shared_key_file_needs_the_same_signing_alg() {
        let e = errs(&format!(
            "{A}key_file = \"k.pem\"\nsigning_alg = \"ES256\"\n\
             [issuer.b]\nissuer_url = \"http://localhost:9000/b/\"\nkey_file = \"k.pem\"\nsigning_alg = \"PS256\"\n"
        ));
        assert_eq!(e.len(), 1, "{e:?}");
        assert!(
            e[0].contains("issuer.a.key_file") && e[0].contains("issuer.b.key_file"),
            "{e:?}"
        );
        let same = errs(&format!(
            "{A}key_file = \"k.pem\"\nsigning_alg = \"ES256\"\n\
             [issuer.b]\nissuer_url = \"http://localhost:9000/b/\"\nkey_file = \"k.pem\"\nsigning_alg = \"ES256\"\n"
        ));
        assert!(same.is_empty(), "{same:?}");
        let server = errs(&format!(
            "[server]\nkey_file = \"k.pem\"\n{A}key_file = \"k.pem\"\nsigning_alg = \"ES256\"\n"
        ));
        assert!(
            server.len() == 1 && server[0].contains("server.key_file"),
            "{server:?}"
        );
    }
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
    fn reserved_issuer_id_static() {
        let e = errs("[issuer.static]\nissuer_url=\"http://h/s\"\n");
        assert_eq!(e.len(), 1, "{e:?}");
        assert!(e[0].contains("issuer id \"static\" is reserved"), "{e:?}");
    }
    #[test]
    fn reserved_custom_user_id() {
        assert_eq!(
            errs(&format!("{A}[user.__custom__]\n")),
            vec!["user id \"__custom__\" is reserved for the Custom user on the login page"]
        );
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
    #[test]
    fn duplicate_endpoint_paths() {
        let e = errs(&format!(
            "{A}paths = {{ token = \"/x\", revoke = \"/x/\" }}\n"
        ));
        assert!(
            e.iter().any(|m| m.contains("paths") && m.contains("/x")),
            "{e:?}"
        );
    }
    #[test]
    fn bad_endpoint_paths() {
        for p in [
            "oauth/token",
            "/",
            "/a?b",
            "/a/{id}",
            "/a//b",
            "/.well-known/x",
            "/a/*",
            "/_mock/health",
            "/_mock",
            "/a b",
            "/a%20b",
            "/a\\b",
            "/a/../b",
            "/a/./b",
        ] {
            assert!(
                !errs(&format!("{A}paths = {{ token = \"{p}\" }}\n")).is_empty(),
                "{p}"
            );
        }
    }
    #[test]
    fn alias_target_must_be_standard() {
        let e = errs(&format!(
            "{A}logout_param_aliases = {{ returnTo = \"redirect\" }}\n"
        ));
        assert!(
            e.iter()
                .any(|m| m.contains("logout_param_aliases") && m.contains("returnTo")),
            "{e:?}"
        );
        assert!(
            errs(&format!(
                "{A}logout_param_aliases = {{ returnTo = \"post_logout_redirect_uri\" }}\n"
            ))
            .is_empty()
        );
    }
    #[test]
    fn alias_key_must_differ_from_target_and_not_be_empty() {
        assert!(
            !errs(&format!(
                "{A}logout_param_aliases = {{ state = \"state\" }}\n"
            ))
            .is_empty()
        );
        assert!(
            !errs(&format!(
                "{A}logout_param_aliases = {{ \"\" = \"state\" }}\n"
            ))
            .is_empty()
        );
    }
    #[test]
    fn client_m2_fields_are_checked() {
        let base = format!("{A}[client.c]\n");
        assert!(!errs(&format!("{base}grant_types = [\"password\"]\n")).is_empty());
        assert!(
            !errs(&format!(
                "{base}post_logout_redirect_uris = [\"not a url\"]\n"
            ))
            .is_empty()
        );
        assert!(
            !errs(&format!(
                "{base}web_origins = [\"http://localhost:3000/app\"]\n"
            ))
            .is_empty()
        );
        assert!(
            errs(&format!(
                "{base}web_origins = [\"http://localhost:3000\", \"https://a.example.com/\"]\n"
            ))
            .is_empty()
        );
    }
    #[test]
    fn client_jwks_must_be_a_jwk_set() {
        let e = errs(&format!(
            "{A}[client.backend]\njwks = {{ keys = [ {{ kty = \"EC\" }} ] }}\n"
        ));
        assert!(e.iter().any(|m| m.contains("client.backend.jwks")), "{e:?}");
        let e = errs(&format!("{A}[client.backend]\njwks = {{ nokeys = 1 }}\n"));
        assert!(e.iter().any(|m| m.contains("client.backend.jwks")), "{e:?}");
    }
    #[test]
    fn client_jwks_and_jwks_uri_are_exclusive() {
        let e = errs(&format!(
            "{A}[client.backend]\njwks = {{ keys = [] }}\njwks_uri = \"http://localhost:1/jwks\"\n"
        ));
        assert!(e.iter().any(|m| m.contains("client.backend")), "{e:?}");
    }
    #[test]
    fn client_jwks_uri_must_be_http() {
        let e = errs(&format!(
            "{A}[client.backend]\njwks_uri = \"https://keys.example.com/jwks\"\n"
        ));
        assert!(
            e.iter()
                .any(|m| m.contains("client.backend.jwks_uri") && m.contains("https")),
            "{e:?}"
        );
        assert!(!errs(&format!("{A}[client.backend]\njwks_uri = \"/jwks\"\n")).is_empty());
        assert!(
            errs(&format!(
                "{A}[client.backend]\njwks_uri = \"http://127.0.0.1:8080/jwks\"\n"
            ))
            .is_empty()
        );
    }
    #[test]
    fn duplicate_path_error_names_a_source() {
        let e = crate::config::load_str(&format!("{A}paths = {{ token = \"/revoke\" }}\n"))
            .unwrap_err();
        assert!(
            e.0.iter()
                .any(|m| m.message.contains("both use") && m.origin != Source::Default),
            "{e:?}"
        );
    }
}
