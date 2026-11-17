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
fn crates_io_publish_is_set_up() {
    for f in ["README.md", "skills/fauxidc/SKILL.md"] {
        let t = read(f);
        assert!(t.contains("cargo install fauxidc --locked"), "{f}");
        assert!(
            t.contains("cargo install --git https://github.com/schmas/fauxidc --locked"),
            "{f}"
        );
    }
    assert!(!read("Cargo.toml").contains("publish = false"));
    let rp = read("release-plz.toml");
    assert!(!rp.contains("publish = false"));
    assert!(!rp.contains("git_only = true"));
    assert!(
        read(".github/workflows/release.yml")
            .contains("CARGO_REGISTRY_TOKEN: ${{ steps.crates-io-auth.outputs.token }}")
    );
    for f in [
        "README.md",
        "AGENTS.md",
        "docs/features.md",
        "docs/spec.md",
        "skills/fauxidc/SKILL.md",
    ] {
        let t = read(f).to_lowercase();
        assert!(!t.contains("no crates.io"), "{f}");
        assert!(!t.contains("without a crates.io"), "{f}");
    }
}

#[test]
fn spec_states_the_m4_rules() {
    let s = read("docs/spec.md");
    for needle in [
        "foreign `Origin` header gives 403 `access_denied`",
        "More than one `audience` or more than one `resource` parameter gives 400 `invalid_request`",
        "At most 256 TLS handshakes run at once",
        "`fauxidc_debugger_<issuer id>`",
        "at most once every 10 s per URL",
        "`https://` when `server.tls` is set",
    ] {
        assert!(s.contains(needle), "{needle}");
    }
    assert!(!s.contains("Otherwise they use `http://` + the request `Host` header"));
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
    // The recipes live in docs/recipes.md. The README lists them with links.
    let recipes = read("docs/recipes.md");
    for recipe in [
        "SPA with PKCE",
        "Backend with a client secret",
        "Machine-to-machine",
        "Mint a token in a test",
        "Random host port (Testcontainers)",
        "Simulate a provider outage",
        "Use with an agent",
    ] {
        assert!(recipes.contains(&format!("\n## {recipe}\n")), "{recipe}");
        assert!(
            r.contains(&format!("[{recipe}](docs/recipes.md#")),
            "{recipe}"
        );
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
fn readme_shows_the_product_at_the_top() {
    let r = read("README.md");
    let first = r
        .lines()
        .find(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("[!["))
        .expect("first line");
    assert!(
        first.contains("OAuth 2.0 / OpenID Connect mock server"),
        "{first}"
    );
    assert!(r.contains(r#"alt="fauxidc: OAuth 2.0 / OpenID Connect mock server""#));
    let why = r.find("## Why fauxidc").expect("why section");
    let hero = r.find("](docs/media/login-flow.gif)").expect("hero GIF");
    assert!(hero < why && why < r.find("## Start in 60 seconds").expect("start section"));
    for media in [
        "banner.svg",
        "login-flow.gif",
        "terminal.gif",
        "inject-failure.gif",
        "login-page.png",
        "debugger.png",
        "dashboard.png",
    ] {
        assert!(r.contains(&format!("docs/media/{media}")), "{media}");
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("docs/media")
            .join(media);
        assert!(path.exists(), "{media}");
    }
    // Every image has alt text.
    assert!(!r.contains("![]("));
    assert!(r.contains("docs/agents.md") && r.contains("docs/footprint.md"));
}

#[test]
fn agents_doc_has_prompts_and_footprint_doc_has_numbers() {
    let a = read("docs/agents.md");
    assert!(a.matches("```text").count() >= 4);
    for needle in [
        "llms.txt",
        "skills/fauxidc/SKILL.md",
        "/_mock/",
        "fail-next",
        "~/.agents/skills/",
    ] {
        assert!(a.contains(needle), "{needle}");
    }
    let f = read("docs/footprint.md");
    for needle in [
        "cargo build --release",
        "ps -o rss=",
        "/_mock/health",
        "macOS",
    ] {
        assert!(f.contains(needle), "{needle}");
    }
}

#[test]
fn testcontainers_guide_covers_the_jvm_setup() {
    let g = read("docs/testcontainers.md");
    for needle in [
        "GenericContainer",
        "ghcr.io/schmas/fauxidc:",
        "withExposedPorts(9000)",
        "withCopyFileToContainer",
        "/config/fauxidc.toml",
        "FAUXIDC__",
        "FAUXIDC_ISSUER_FROM_HOST",
        "Wait.forHttp(\"/_mock/health\")",
        r#"\"key\":\"ready\""#,
        "setPortBindings",
        "@DynamicPropertySource",
        "spring.security.oauth2.resourceserver.jwt.issuer-uri",
        "at+jwt",
        "java.net.http.HttpClient",
        "/_mock/default/token",
        "no Java module",
    ] {
        assert!(g.contains(needle), "{needle}");
    }
    for f in [
        "README.md",
        "llms.txt",
        "docs/configuration.md",
        "skills/fauxidc/SKILL.md",
    ] {
        assert!(read(f).contains("testcontainers.md"), "{f}");
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

#[test]
fn agents_md_has_six_sections_and_fits() {
    let a = read("AGENTS.md");
    let n = a.lines().count();
    assert!((80..=120).contains(&n), "{n} lines");
    let heads: Vec<&str> = a.lines().filter(|l| l.starts_with("## ")).collect();
    assert_eq!(
        heads,
        [
            "## Project Overview",
            "## Tech Stack",
            "## Commands",
            "## Directory Structure",
            "## Conventions",
            "## Rules"
        ]
    );
    assert!(!a.contains("Rejected, with reason"));
}

#[test]
fn agents_md_keeps_every_rule() {
    let a = read("AGENTS.md");
    for rule in [
        "TDD",
        "cargo fmt --check",
        "clippy",
        "ADR",
        "unsafe",
        "unwrap()",
        "C toolchain",
        "real companies",
        "CDN",
    ] {
        assert!(a.contains(rule), "{rule}");
    }
}

#[test]
fn skill_has_front_matter_and_fits() {
    for name in ["fauxidc", "fauxidc-setup"] {
        let s = read(&format!("skills/{name}/SKILL.md"));
        assert!(
            s.starts_with(&format!("---\nname: {name}\ndescription: Use when ")),
            "{name}"
        );
        assert!(
            s.lines().count() < 200,
            "{name}: {} lines",
            s.lines().count()
        );
    }
}

const SETUP_TEMPLATES: [&str; 4] = ["fauxidc.toml", "compose.yml", "idp.sh", "README.md"];

/// A setup template with every `{{placeholder}}` filled in.
fn filled_template(file: &str) -> String {
    let mut t = read(&format!("skills/fauxidc-setup/templates/{file}"));
    for (key, value) in [
        ("issuer_id", "local"),
        ("port", "9400"),
        ("client_id", "example-app"),
        ("client_secret", "local-secret"),
        ("redirect_uri", "http://localhost:3000/api/auth/callback/*"),
        ("app_url", "http://localhost:3000"),
        ("image_tag", "0.4.0"),
        ("project_name", "example-app-idp"),
    ] {
        t = t.replace(&format!("{{{{{key}}}}}"), value);
    }
    t
}

#[test]
fn setup_skill_names_its_templates_and_steps() {
    let s = read("skills/fauxidc-setup/SKILL.md");
    for file in SETUP_TEMPLATES {
        assert!(s.contains(&format!("templates/{file}")), "{file}");
        let t = filled_template(file);
        assert!(!t.contains("{{"), "{file} has an unknown placeholder");
    }
    for needle in [
        "config --check",
        "/.well-known/openid-configuration",
        "/_mock/",
        "/debugger",
        "/endsession",
        "issuer_from_host",
        "key_file",
        "Strict mode",
    ] {
        assert!(s.contains(needle), "{needle}");
    }
}

#[test]
fn setup_templates_are_valid() {
    let config = filled_template("fauxidc.toml");
    assert!(config.starts_with("#:schema https://raw.githubusercontent.com/schmas/fauxidc/"));
    let path = std::env::temp_dir().join(format!("fauxidc-setup-{}.toml", std::process::id()));
    std::fs::write(&path, &config).unwrap();
    let loaded = fauxidc::config::load(&fauxidc::config::LoadInputs {
        config_files: vec![path.clone()],
        env: vec![],
        flags: fauxidc::config::CliOverrides::default(),
        cwd: ".".into(),
    });
    std::fs::remove_file(&path).unwrap();
    let config = loaded.unwrap_or_else(|e| panic!("{e}")).config;
    let issuer = &config.issuer["local"];
    assert_eq!(issuer.issuer_url, "http://localhost:9400/local");
    assert!(!issuer.lenient, "Strict mode");
    assert!(
        !config.server.key_file.is_empty(),
        "the key survives a recreate"
    );

    let compose = filled_template("compose.yml");
    for needle in [
        "ghcr.io/schmas/fauxidc:0.4.0",
        "127.0.0.1:9400:9000",
        "./fauxidc.toml:/config/fauxidc.toml:ro",
        "healthcheck:",
        "name: example-app-idp",
    ] {
        assert!(compose.contains(needle), "{needle}");
    }
    let script = filled_template("idp.sh");
    for command in ["up)", "down)", "status)", "logs)", "token)", "check)"] {
        assert!(script.contains(command), "{command}");
    }
    let readme = filled_template("README.md");
    assert!(readme.contains("http://localhost:9400/local/endsession"));
}

#[test]
fn skill_covers_the_pitfalls() {
    let s = read("skills/fauxidc/SKILL.md");
    for needle in [
        "issuer_url",
        "Host",
        "Lenient",
        "redirect_uri",
        "/_mock/",
        "fail-next",
        "/debugger",
        "fauxidc.schema.json",
        "at+jwt",
    ] {
        assert!(s.contains(needle), "{needle}");
    }
}

#[test]
fn llms_txt_lists_the_docs() {
    let l = read("llms.txt");
    assert!(l.starts_with("# fauxidc\n\n> "));
    for needle in [
        "## Docs",
        "## Config",
        "## Agent skill",
        "README.md#start-in-60-seconds",
        "docs/templates.md",
        "schema/fauxidc.schema.json",
        "examples/cognito.toml",
        "skills/fauxidc/SKILL.md",
        "skills/fauxidc-setup/SKILL.md",
    ] {
        assert!(l.contains(needle), "{needle}");
    }
}

#[test]
fn recipes_work_for_every_install_path() {
    let r = read("README.md");
    assert!(r.contains("--config /examples/generic.toml"));
    assert!(r.contains("raw.githubusercontent.com/schmas/fauxidc/main/examples/generic.toml"));
    assert!(r.contains("/usr/local/bin"));
    assert!(r.contains("com.apple.quarantine"));
    for f in ["README.md", "skills/fauxidc/SKILL.md"] {
        let t = read(f);
        assert!(
            t.contains("cargo install --git https://github.com/schmas/fauxidc --locked"),
            "{f}"
        );
        assert!(t.contains("--tag v0.1.0") && t.contains("1.98"), "{f}");
    }
}

#[test]
fn readme_says_how_to_install_the_skill() {
    let r = read("README.md");
    assert!(r.contains("skills/fauxidc"));
    assert!(r.contains(".claude/skills/") && r.contains("~/.agents/skills/"));
    assert!(r.contains("~/.claude/skills/"));
}

/// The lines of `text` outside fenced code blocks.
fn prose_lines(text: &str) -> Vec<&str> {
    let mut in_fence = false;
    let mut out = Vec::new();
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if !in_fence {
            out.push(line);
        }
    }
    out
}

/// GitHub heading anchors of a Markdown file: lowercase, spaces to `-`, other punctuation dropped.
fn anchors(text: &str) -> Vec<String> {
    prose_lines(text)
        .into_iter()
        .filter(|l| l.starts_with('#'))
        .map(|l| {
            l.trim_start_matches('#')
                .trim()
                .to_lowercase()
                .chars()
                .filter_map(|c| match c {
                    ' ' => Some('-'),
                    c if c.is_alphanumeric() || c == '-' || c == '_' => Some(c),
                    _ => None,
                })
                .collect()
        })
        .collect()
}

/// The targets of the inline Markdown links `[text](target)` outside code blocks.
fn link_targets(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in prose_lines(text) {
        let mut rest = line;
        while let Some(at) = rest.find("](") {
            rest = &rest[at + 2..];
            if let Some(end) = rest.find(')') {
                out.push(rest[..end].to_owned());
                rest = &rest[end..];
            }
        }
    }
    out
}

#[test]
fn doc_links_resolve() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = vec![
        "README.md".to_owned(),
        "llms.txt".to_owned(),
        "skills/fauxidc/SKILL.md".to_owned(),
        "skills/fauxidc-setup/SKILL.md".to_owned(),
        "skills/fauxidc-setup/templates/README.md".to_owned(),
        "AGENTS.md".to_owned(),
        "CONTRIBUTING.md".to_owned(),
    ];
    for entry in std::fs::read_dir(root.join("docs")).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        if Path::new(&name).extension().is_some_and(|e| e == "md") {
            files.push(format!("docs/{name}"));
        }
    }
    let mut broken = Vec::new();
    for file in &files {
        let text = read(file);
        let dir = Path::new(file).parent().unwrap();
        for target in link_targets(&text) {
            if ["http:", "https:", "mailto:"]
                .iter()
                .any(|p| target.starts_with(p))
            {
                continue;
            }
            let (path, anchor) = match target.split_once('#') {
                Some((p, a)) => (p, Some(a)),
                None => (target.as_str(), None),
            };
            let linked = if path.is_empty() {
                Path::new(file).to_path_buf()
            } else {
                dir.join(path)
            };
            let full = root.join(&linked);
            if !full.exists() {
                broken.push(format!("{file}: {target} (no file)"));
                continue;
            }
            if let Some(anchor) = anchor {
                let linked_text = std::fs::read_to_string(&full).unwrap_or_default();
                if !anchors(&linked_text).iter().any(|a| a == anchor) {
                    broken.push(format!("{file}: {target} (no anchor)"));
                }
            }
        }
    }
    assert!(broken.is_empty(), "{broken:#?}");
}
