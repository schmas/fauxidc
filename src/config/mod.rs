pub mod types;
pub use types::*;
pub mod layers;
pub mod load;
pub mod merge;
pub mod source;

pub use layers::{env_layer, file_layer, flag_layer, inline_layer};
pub use load::{CliOverrides, LoadInputs, Loaded, load};
pub use merge::deep_merge;
pub use source::{KeyPath, Layer, Source, SourceMap};

#[cfg(test)]
pub(crate) mod test_util {
    use super::{CliOverrides, KeyPath, LoadInputs};

    /// Builds a key path from a dotted string such as `server.port`.
    pub fn path(dotted: &str) -> KeyPath {
        dotted.split('.').map(str::to_owned).collect()
    }

    /// Builds an owned list of env vars from string pairs.
    pub fn vars(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter()
            .map(|(a, b)| ((*a).to_string(), (*b).to_string()))
            .collect()
    }

    /// Writes `text` to a new temporary TOML file and returns its path.
    pub fn write_tmp(text: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("fauxidc-test-{}.toml", uuid::Uuid::new_v4()));
        std::fs::write(&path, text).unwrap();
        path
    }

    /// Creates a new empty temporary directory and returns its path.
    pub fn empty_tmp_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("fauxidc-test-dir-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Builds load inputs with no files, no flags and an empty working directory.
    pub fn inputs(env: &[(&str, &str)]) -> LoadInputs {
        LoadInputs {
            config_files: vec![],
            env: vars(env),
            flags: CliOverrides::default(),
            cwd: empty_tmp_dir(),
        }
    }
}
