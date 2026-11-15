mod common;
use common::*;

#[test]
fn example_configs_are_valid() {
    for f in ["examples/auth0.toml", "examples/okta.toml"] {
        let i = fauxidc::config::LoadInputs {
            config_files: vec![f.into()],
            env: vec![],
            flags: fauxidc::config::CliOverrides::default(),
            cwd: ".".into(),
        };
        let l = fauxidc::config::load(&i).unwrap_or_else(|e| panic!("{f}: {e}"));
        assert!(!l.zero_config);
    }
}

#[tokio::test]
async fn examples_merge_and_publish_paths() {
    let i = fauxidc::config::LoadInputs {
        config_files: vec!["examples/auth0.toml".into(), "examples/okta.toml".into()],
        env: vec![],
        flags: fauxidc::config::CliOverrides::default(),
        cwd: ".".into(),
    };
    let app = app_from_config(fauxidc::config::load(&i).unwrap().config);
    let a = json(
        &send(&app, get("/auth0/.well-known/openid-configuration"))
            .await
            .2,
    );
    assert_eq!(
        a["token_endpoint"],
        "http://localhost:9000/auth0/oauth/token"
    );
    assert_eq!(
        a["end_session_endpoint"],
        "http://localhost:9000/auth0/v2/logout"
    );
    let o = json(
        &send(
            &app,
            get("/oauth2/default/.well-known/openid-configuration"),
        )
        .await
        .2,
    );
    assert_eq!(
        o["jwks_uri"],
        "http://localhost:9000/oauth2/default/v1/keys"
    );
    assert_eq!(
        o["revocation_endpoint"],
        "http://localhost:9000/oauth2/default/v1/revoke"
    );
}
