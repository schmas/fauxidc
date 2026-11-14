//! Where a configuration value came from, and layers of values.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

/// The origin of a configuration value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Default,
    File { path: PathBuf, line: Option<usize> },
    Inline,
    Env(String),
    Flag(&'static str),
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Source::Default => write!(f, "default"),
            Source::File {
                path,
                line: Some(line),
            } => write!(f, "{}:{line}", path.display()),
            Source::File { path, line: None } => write!(f, "{}", path.display()),
            Source::Inline => write!(f, "inline"),
            Source::Env(name) => write!(f, "env {name}"),
            Source::Flag(name) => write!(f, "flag {name}"),
        }
    }
}

/// A path of table keys, such as `["server", "port"]`.
pub type KeyPath = Vec<String>;

/// The source of every leaf value, by key path.
pub type SourceMap = BTreeMap<KeyPath, Source>;

/// A table of values and the source of each leaf.
///
/// A leaf is any non-table value, arrays included.
#[derive(Debug, Clone, Default)]
pub struct Layer {
    pub table: toml::Table,
    pub sources: SourceMap,
}

impl Layer {
    /// Builds a layer and records `source` for every leaf.
    #[allow(clippy::needless_pass_by_value)] // the signature takes the source by value
    pub fn from_table(table: toml::Table, source: Source) -> Layer {
        let mut sources = SourceMap::new();
        record_leaves(&table, &mut Vec::new(), &source, &mut sources);
        Layer { table, sources }
    }
}

fn record_leaves(
    table: &toml::Table,
    prefix: &mut KeyPath,
    source: &Source,
    sources: &mut SourceMap,
) {
    for (key, value) in table {
        prefix.push(key.clone());
        match value {
            toml::Value::Table(inner) => record_leaves(inner, prefix, source, sources),
            _ => {
                sources.insert(prefix.clone(), source.clone());
            }
        }
        prefix.pop();
    }
}
