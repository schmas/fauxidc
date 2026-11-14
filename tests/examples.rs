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
