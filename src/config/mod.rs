pub mod types;
pub use types::*;
pub mod merge;
pub mod source;

pub use merge::deep_merge;
pub use source::{KeyPath, Layer, Source, SourceMap};

#[cfg(test)]
pub(crate) mod test_util {
    use super::KeyPath;

    /// Builds a key path from a dotted string such as `server.port`.
    pub fn path(dotted: &str) -> KeyPath {
        dotted.split('.').map(str::to_owned).collect()
    }
}
