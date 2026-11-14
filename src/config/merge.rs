//! Deep merge of configuration layers.

use super::source::{KeyPath, Layer};

/// Merges `top` into `base`.
///
/// Tables merge key by key. Any other value, arrays included, replaces the old value.
/// When a value replaces a table, or a table replaces a value, the old leaf sources
/// under that path are removed.
pub fn deep_merge(base: &mut Layer, top: Layer) {
    let Layer { table, sources } = top;
    merge_tables(&mut base.table, table, &mut Vec::new(), &mut base.sources);
    base.sources.extend(sources);
}

fn merge_tables(
    base: &mut toml::Table,
    top: toml::Table,
    prefix: &mut KeyPath,
    sources: &mut super::source::SourceMap,
) {
    for (key, value) in top {
        prefix.push(key.clone());
        match (base.get_mut(&key), value) {
            (Some(toml::Value::Table(base_inner)), toml::Value::Table(top_inner)) => {
                merge_tables(base_inner, top_inner, prefix, sources);
            }
            (existing, value) => {
                if existing.is_some() {
                    sources.retain(|k, _| !k.starts_with(prefix.as_slice()));
                }
                base.insert(key, value);
            }
        }
        prefix.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Source;
    use crate::config::test_util::*;

    fn layer(s: &str, src: Source) -> Layer {
        Layer::from_table(toml::from_str(s).unwrap(), src)
    }

    #[test]
    fn later_scalar_wins_and_tables_merge() {
        let mut base = layer("[server]\nport = 1\nbind = \"a\"", Source::Default);
        deep_merge(&mut base, layer("[server]\nport = 2", Source::Inline));
        assert_eq!(base.table["server"]["port"].as_integer(), Some(2));
        assert_eq!(base.table["server"]["bind"].as_str(), Some("a"));
        assert_eq!(base.sources[&path("server.port")], Source::Inline);
        assert_eq!(base.sources[&path("server.bind")], Source::Default);
    }

    #[test]
    fn arrays_replace_not_append() {
        let mut base = layer("[client.c]\nscopes = [\"a\", \"b\"]", Source::Default);
        deep_merge(
            &mut base,
            layer("[client.c]\nscopes = [\"x\"]", Source::Inline),
        );
        assert_eq!(
            base.table["client"]["c"]["scopes"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn env_can_add_new_entry() {
        let mut base = layer("[user.alice]\nlabel = \"A\"", Source::Default);
        deep_merge(
            &mut base,
            layer(
                "[user.bob]\nlabel = \"B\"",
                Source::Env("FAUXIDC__USER__BOB__LABEL".into()),
            ),
        );
        assert!(
            base.table["user"].get("alice").is_some() && base.table["user"].get("bob").is_some()
        );
    }

    #[test]
    fn replacing_a_table_with_a_value_drops_old_leaf_sources() {
        let mut base = layer("[a]\nx = 1\ny = 2", Source::Default);
        deep_merge(&mut base, layer("a = 5", Source::Inline));
        assert_eq!(base.sources.len(), 1);
        assert_eq!(base.sources[&path("a")], Source::Inline);
    }

    #[test]
    fn replacing_a_value_with_a_table_drops_old_leaf_source() {
        let mut base = layer("a = 5", Source::Default);
        deep_merge(&mut base, layer("[a]\nx = 1", Source::Inline));
        assert_eq!(base.sources.len(), 1);
        assert_eq!(base.sources[&path("a.x")], Source::Inline);
    }

    #[test]
    fn source_display() {
        use std::path::PathBuf;
        let file = |line| Source::File {
            path: PathBuf::from("file.toml"),
            line,
        };
        assert_eq!(file(Some(12)).to_string(), "file.toml:12");
        assert_eq!(file(None).to_string(), "file.toml");
        assert_eq!(
            Source::Env("FAUXIDC__X".into()).to_string(),
            "env FAUXIDC__X"
        );
        assert_eq!(Source::Flag("--port").to_string(), "flag --port");
        assert_eq!(Source::Default.to_string(), "default");
        assert_eq!(Source::Inline.to_string(), "inline");
    }
}
