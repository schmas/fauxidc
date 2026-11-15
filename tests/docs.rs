//! Checks that the docs state what users need to know.

use std::path::Path;

/// Reads a repo file, relative to the crate root.
pub fn read(path: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .unwrap_or_else(|e| panic!("cannot read {path}: {e}"))
}

#[test]
fn readme_documents_sessions() {
    let r = format!("{}\n{}", read("README.md"), read("docs/features.md"));
    assert!(read("docs/features.md").contains("\n## Sessions\n"));
    for needle in [
        "fauxidc_session_",
        "prompt=none",
        "login_required",
        "max_age=0",
        "Auto-select",
        "/endsession",
    ] {
        assert!(r.contains(needle), "{needle}");
    }
    assert!(r.contains("closing the terminal does not stop"));
    assert!(r.contains("/debugger/callback` in `redirect_uris`"));
}

#[test]
fn readme_describes_the_reload_debounce() {
    let r = read("README.md");
    assert!(r.contains("two polls"));
    assert!(r.contains("1 to 2 s after the save"));
    assert!(!r.contains("within about 1 s"));
}

#[test]
fn no_crates_io_publish() {
    let rp = read("release-plz.toml");
    assert!(rp.contains("publish = false"));
    assert!(rp.contains("git_only = true"));
    assert!(!read(".github/workflows/release.yml").contains("CARGO_REGISTRY_TOKEN"));
    for f in ["README.md", "CONTRIBUTING.md", "docs/spec.md"] {
        assert!(!read(f).contains("cargo install fauxidc"), "{f}");
    }
}

const DISCLAIMER: &str = "fauxidc was designed and built with AI coding agents (Claude Code), under human direction and review. Every change passes the test suite, clippy, and the OpenID conformance suite in CI. Report problems in GitHub issues.";

#[test]
fn readme_has_the_disclaimer_near_the_top() {
    let r = read("README.md");
    let at = r.find(DISCLAIMER).expect("disclaimer");
    assert!(at < r.find("## Start in 60 seconds").expect("start section"));
}

#[test]
fn readme_is_short_and_ordered() {
    let r = read("README.md");
    assert!(r.lines().count() < 350, "{} lines", r.lines().count());
    let order = [
        "## Start in 60 seconds",
        "## Recipes",
        "## Configuration",
        "## Test API",
        "## Templates",
        "## Debugger",
        "## TLS",
        "## Hot reload",
        "## Conformance",
        "## Not supported",
    ];
    let pos: Vec<usize> = order
        .iter()
        .map(|h| r.find(h).unwrap_or_else(|| panic!("{h}")))
        .collect();
    assert!(pos.windows(2).all(|w| w[0] < w[1]));
    for recipe in [
        "SPA with PKCE",
        "Backend with a client secret",
        "Machine-to-machine",
        "Mint a token in a test",
        "Simulate a provider outage",
        "Use with an agent",
    ] {
        assert!(r.contains(&format!("### {recipe}")), "{recipe}");
    }
    assert!(r.contains("ghcr.io/schmas/fauxidc") && r.contains("img.shields.io/github/v/release"));
    for example in [
        "auth0.toml",
        "okta.toml",
        "generic.toml",
        "keycloak.toml",
        "entra.toml",
        "cognito.toml",
    ] {
        assert!(r.contains(example), "{example}");
    }
}

#[test]
fn templates_doc_states_the_custom_user_override_rules() {
    let t = read("docs/templates.md");
    assert!(t.contains("checked (it must be a JSON object) but not applied"));
    assert!(t.contains("merged on top of the template claims"));
    assert!(t.contains("changes `sub` too"));
    assert!(t.contains("must render the `username` field when `custom_username` is `true`"));
}
