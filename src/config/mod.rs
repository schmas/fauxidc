pub mod types;
pub use types::*;
pub mod layers;
pub mod merge;
pub mod source;

pub use layers::{file_layer, inline_layer};
pub use merge::deep_merge;
pub use source::{KeyPath, Layer, Source, SourceMap};

#[cfg(test)]
pub(crate) mod test_util {
    use super::KeyPath;

    /// Builds a key path from a dotted string such as `server.port`.
    pub fn path(dotted: &str) -> KeyPath {
        dotted.split('.').map(str::to_owned).collect()
    }

    /// Writes `text` to a new temporary TOML file and returns its path.
    pub fn write_tmp(text: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("fauxidc-test-{}.toml", uuid::Uuid::new_v4()));
        std::fs::write(&path, text).unwrap();
        path
    }
}
