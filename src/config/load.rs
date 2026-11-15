//! Loading and merging of all configuration layers.

use std::path::PathBuf;

use super::layers::ENV_PREFIX;
use super::types::{Config, LogFormat};
use super::{
    Layer, Source, SourceMap, deep_merge, env_layer, file_layer, flag_layer, inline_layer, validate,
};
use crate::error::{ConfigError, ConfigErrors};

/// Settings given as command-line flags.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CliOverrides {
    pub port: Option<u16>,
    pub bind: Option<String>,
    pub log_format: Option<LogFormat>,
}

/// Everything `load` reads: files, env vars, flags and the working directory.
#[derive(Debug, Clone)]
pub struct LoadInputs {
    pub config_files: Vec<PathBuf>,
    pub env: Vec<(String, String)>,
    pub flags: CliOverrides,
    pub cwd: PathBuf,
}

/// The merged configuration, the source of each value, the zero-config flag and the config
/// files that were read.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub config: Config,
    pub sources: SourceMap,
    pub zero_config: bool,
    /// The resolved config files (given, `FAUXIDC_CONFIG` or `./fauxidc.toml`). Hot reload
    /// polls them. Empty for Zero config and for `load_str`.
    pub files: Vec<PathBuf>,
}

impl LoadInputs {
    /// Reads the process env vars and the working directory.
    pub fn from_process(
        config_files: Vec<PathBuf>,
        flags: CliOverrides,
    ) -> std::io::Result<LoadInputs> {
        Ok(LoadInputs {
            config_files,
            env: std::env::vars().collect(),
            flags,
            cwd: std::env::current_dir()?,
        })
    }
}

const ZERO_CONFIG: &str = include_str!("zero.toml");

/// Loads and merges all sources, then checks the result.
///
/// The order is base, files, inline, env, flags. Errors from all layers are
/// collected before the function returns.
pub fn load(inputs: &LoadInputs) -> Result<Loaded, ConfigErrors> {
    let env_value = |name: &str| {
        inputs
            .env
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };
    let files = resolve_files(inputs, env_value("FAUXIDC_CONFIG"));
    let inline = env_value("FAUXIDC_CONFIG_INLINE").filter(|text| !text.is_empty());
    let has_env_overrides = inputs.env.iter().any(|(name, _)| {
        name.get(..ENV_PREFIX.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(ENV_PREFIX))
    });
    let zero_config = files.is_empty() && inline.is_none() && !has_env_overrides;

    let mut errors = Vec::new();
    let mut merged = Layer::default();
    if zero_config {
        match zero_layer() {
            Ok(layer) => deep_merge(&mut merged, layer),
            Err(error) => errors.push(error),
        }
    }
    for file in &files {
        match file_layer(file) {
            Ok(layer) => deep_merge(&mut merged, layer),
            Err(error) => errors.push(error),
        }
    }
    if let Some(text) = inline {
        match inline_layer(text) {
            Ok(layer) => deep_merge(&mut merged, layer),
            Err(error) => errors.push(error),
        }
    }
    match env_layer(&inputs.env) {
        Ok(layer) => deep_merge(&mut merged, layer),
        Err(found) => errors.extend(found.0),
    }
    deep_merge(&mut merged, flag_layer(&inputs.flags));
    if !errors.is_empty() {
        return Err(ConfigErrors(errors));
    }

    let mut loaded = finish(merged, zero_config)?;
    loaded.files = files;
    if zero_config && let Some(default) = loaded.config.issuer.get_mut("default") {
        // The Zero config Issuer URL follows the effective port, for example from `--port`.
        default.issuer_url = format!("http://localhost:{}/default", loaded.config.server.port);
    }
    Ok(loaded)
}

/// Loads an inline layer (TOML or JSON) as the only source, then checks the result.
///
/// There is no Zero config, no env and no flags. For tests and the library API.
pub fn load_str(text: &str) -> Result<Loaded, ConfigErrors> {
    let layer = inline_layer(text).map_err(|e| ConfigErrors(vec![e]))?;
    finish(layer, false)
}

/// Turns a merged layer into a checked configuration.
fn finish(merged: Layer, zero_config: bool) -> Result<Loaded, ConfigErrors> {
    let Layer { table, sources } = merged;
    let config = toml::Value::Table(table)
        .try_into::<Config>()
        .map_err(|e| {
            ConfigErrors(vec![ConfigError {
                origin: Source::Default,
                message: e.to_string(),
            }])
        })?;
    validate(&config, &sources)?;
    Ok(Loaded {
        config,
        sources,
        zero_config,
        files: Vec::new(),
    })
}

fn resolve_files(inputs: &LoadInputs, env_list: Option<&str>) -> Vec<PathBuf> {
    if !inputs.config_files.is_empty() {
        return inputs.config_files.clone();
    }
    if let Some(list) = env_list {
        let listed: Vec<PathBuf> = list
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(PathBuf::from)
            .collect();
        if !listed.is_empty() {
            return listed;
        }
    }
    let local = inputs.cwd.join("fauxidc.toml");
    if local.exists() {
        vec![local]
    } else {
        Vec::new()
    }
}

fn zero_layer() -> Result<Layer, ConfigError> {
    let table = toml::from_str::<toml::Table>(ZERO_CONFIG).map_err(|e| ConfigError {
        origin: Source::Default,
        message: e.to_string(),
    })?;
    Ok(Layer::from_table(table, Source::Default))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Source;
    use crate::config::test_util::*;

    #[test]
    fn zero_config_when_nothing_given() {
        let l = load(&inputs(&[])).unwrap();
        assert!(l.zero_config);
        assert_eq!(
            l.config.issuer["default"].issuer_url,
            "http://localhost:9000/default"
        );
        assert!(l.config.issuer["default"].lenient);
        assert!(l.config.client["test"].client_secret.is_none());
        assert_eq!(l.config.user.len(), 2);
    }

    #[test]
    fn flags_keep_zero_config() {
        let mut i = inputs(&[]);
        i.flags.bind = Some("0.0.0.0".into());
        let l = load(&i).unwrap();
        assert!(l.zero_config);
        assert_eq!(l.config.server.bind, "0.0.0.0");
    }

    #[test]
    fn zero_config_issuer_url_follows_port_flag() {
        let mut i = inputs(&[]);
        i.flags.port = Some(9100);
        let l = load(&i).unwrap();
        assert!(l.zero_config);
        assert_eq!(l.config.server.port, 9100);
        assert_eq!(
            l.config.issuer["default"].issuer_url,
            "http://localhost:9100/default"
        );
    }

    #[test]
    fn env_override_turns_off_zero_config() {
        let l = load(&inputs(&[(
            "FAUXIDC__ISSUER__A__ISSUER_URL",
            "http://localhost:9000/a",
        )]))
        .unwrap();
        assert!(!l.zero_config);
        assert!(l.config.issuer.contains_key("a") && !l.config.issuer.contains_key("default"));
    }

    #[test]
    fn paths_from_env() {
        let loaded = load(&inputs(&[
            (
                "FAUXIDC_CONFIG_INLINE",
                "[issuer.auth0]\nissuer_url = \"http://localhost:9000/auth0/\"",
            ),
            ("FAUXIDC__ISSUER__AUTH0__PATHS__TOKEN", "/oauth/token"),
        ]))
        .unwrap();
        assert_eq!(loaded.config.issuer["auth0"].paths.token, "/oauth/token");
    }

    #[test]
    fn precedence_file_inline_env_flag() {
        let f =
            write_tmp("[server]\nport = 1\n[issuer.a]\nissuer_url = \"http://localhost:9000/a\"");
        let mut i = inputs(&[
            ("FAUXIDC_CONFIG_INLINE", "[server]\nport = 2"),
            ("FAUXIDC__SERVER__PORT", "3"),
        ]);
        i.config_files = vec![f];
        assert_eq!(load(&i).unwrap().config.server.port, 3);
        i.flags.port = Some(4);
        let l = load(&i).unwrap();
        assert_eq!(l.config.server.port, 4);
        assert_eq!(l.sources[&path("server.port")], Source::Flag("--port"));
    }

    #[test]
    fn fauxidc_config_env_lists_files_and_cwd_fallback() {
        let a = write_tmp("[issuer.a]\nissuer_url = \"http://localhost:9000/a\"");
        let b = write_tmp("[issuer.a]\nlenient = true");
        let l = load(&inputs(&[(
            "FAUXIDC_CONFIG",
            &format!("{}, {}", a.display(), b.display()),
        )]))
        .unwrap();
        assert!(l.config.issuer["a"].lenient);

        let mut i = inputs(&[]);
        std::fs::write(
            i.cwd.join("fauxidc.toml"),
            "[issuer.b]\nissuer_url = \"http://localhost:9000/b\"",
        )
        .unwrap();
        assert!(load(&i).unwrap().config.issuer.contains_key("b"));
        i.cwd = empty_tmp_dir();
        assert!(load(&i).unwrap().zero_config);
    }

    #[test]
    fn loaded_files_lists_the_resolved_files() {
        let a = write_tmp("[issuer.a]\nissuer_url = \"http://localhost:9000/a\"");
        let mut i = inputs(&[]);
        i.config_files = vec![a.clone()];
        assert_eq!(load(&i).unwrap().files, vec![a.clone()]);

        let l = load(&inputs(&[("FAUXIDC_CONFIG", a.to_str().unwrap())])).unwrap();
        assert_eq!(l.files, vec![a]);

        let i = inputs(&[]);
        let local = i.cwd.join("fauxidc.toml");
        std::fs::write(
            &local,
            "[issuer.b]\nissuer_url = \"http://localhost:9000/b\"",
        )
        .unwrap();
        assert_eq!(load(&i).unwrap().files, vec![local]);

        let l = load(&inputs(&[])).unwrap();
        assert!(l.zero_config);
        assert_eq!(l.files, Vec::<PathBuf>::new());
    }

    #[test]
    fn errors_from_all_layers_are_collected() {
        let f = write_tmp("[server]\nprot = 1");
        let mut i = inputs(&[("FAUXIDC__SERVER__X", "1")]);
        i.config_files = vec![f];
        assert_eq!(load(&i).unwrap_err().0.len(), 2);
    }

    #[test]
    fn env_without_issuer_fails_validation() {
        let e = load(&inputs(&[("FAUXIDC__SERVER__PORT", "1")])).unwrap_err();
        assert_eq!(e.0.len(), 1);
        assert_eq!(e.0[0].message, "no issuer configured");
    }
}
