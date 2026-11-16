//! Edits of one entry of the config file: a User (`[user.<id>]`) or a Client
//! (`[client.<key>]`).
//!
//! The Test API and the `fauxidc users` and `fauxidc clients` commands share this code (ADR 0008):
//!
//! 1. Load the merged config. The write target is the last config file.
//! 2. Refuse an entry that a source other than the target file sets (an earlier file, inline
//!    config or an env var): a write to the target file would not replace it.
//! 3. Change the target file text with `toml_edit`, so comments and formatting stay.
//! 4. Load the config again with the new text. On an error, the file does not change.
//! 5. [`Edit::write`] writes the new text atomically: a temporary file, then a rename.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use toml_edit::{DocumentMut, Item, Table};

use super::{Config, LoadInputs, Loaded, Source, load, load_with_file_text};
use crate::error::ConfigErrors;

/// A table of entries keyed by id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    /// `[user.<id>]`
    User,
    /// `[client.<key>]`
    Client,
}

impl Section {
    /// The top-level config key.
    pub fn key(self) -> &'static str {
        match self {
            Section::User => "user",
            Section::Client => "client",
        }
    }

    /// The glossary term, for messages.
    pub fn noun(self) -> &'static str {
        match self {
            Section::User => "User",
            Section::Client => "Client",
        }
    }

    fn contains(self, config: &Config, id: &str) -> bool {
        match self {
            Section::User => config.user.contains_key(id),
            Section::Client => config.client.contains_key(id),
        }
    }
}

/// What to do with the entry.
#[derive(Debug, Clone)]
pub enum Change {
    /// Add a new entry. Fails if the id exists.
    Create(Table),
    /// Replace an existing entry.
    Replace(Table),
    /// Remove an existing entry.
    Remove,
}

/// Why an edit was refused. Nothing was written.
#[derive(Debug, thiserror::Error)]
pub enum EditError {
    /// The id does not match `[a-z0-9_]+`.
    #[error("invalid id {0:?}: ids must match [a-z0-9_]+")]
    InvalidId(String),
    /// The new entry is not valid input, for example an unknown field or a JSON `null`.
    #[error("{0}")]
    BadInput(String),
    /// The current config, or the config after the edit, is not valid.
    #[error("invalid configuration:\n{0}")]
    Invalid(ConfigErrors),
    /// No config file is loaded (Zero config, inline config or env vars only).
    #[error("no config file is loaded: changes are written to the last config file (--config)")]
    NoFile,
    /// The entry exists (create).
    #[error("{} {id} already exists", .section.noun())]
    Exists { section: Section, id: String },
    /// The entry does not exist (replace or remove).
    #[error("unknown {}: {id}", .section.key())]
    NotFound { section: Section, id: String },
    /// A source other than the target file sets a value of the entry.
    #[error(
        "{} {id} is set in {origin}: only entries from {} can be changed",
        .section.noun(),
        .target.display()
    )]
    Conflict {
        section: Section,
        id: String,
        origin: Source,
        target: PathBuf,
    },
    /// The entry is a Client that Lenient mode registered in memory. No config file holds it.
    #[error(
        "Client {id} is a Lenient-registered Client in memory and cannot change: \
         create a Client with this client_id instead"
    )]
    Lenient { id: String },
    /// The target file could not be parsed for editing.
    #[error("cannot edit {}: {message}", .path.display())]
    Parse { path: PathBuf, message: String },
}

impl EditError {
    /// `true` for invalid input or config: the CLI exits with code 2, the Test API answers 400.
    pub fn is_config_error(&self) -> bool {
        matches!(
            self,
            EditError::Invalid(_) | EditError::InvalidId(_) | EditError::BadInput(_)
        )
    }
}

/// A checked edit, not written yet.
#[derive(Debug)]
pub struct Edit {
    /// The target file.
    pub path: PathBuf,
    /// The file text before the edit.
    pub old_text: String,
    /// The file text after the edit.
    pub new_text: String,
    /// The config loaded with the new text.
    pub loaded: Loaded,
}

impl Edit {
    /// Writes the new text atomically.
    pub fn write(&self) -> std::io::Result<()> {
        write_atomic(&self.path, &self.new_text)
    }

    /// Writes the old text back atomically.
    pub fn restore(&self) -> std::io::Result<()> {
        write_atomic(&self.path, &self.old_text)
    }
}

/// `true` when `id` matches `[a-z0-9_]+`.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Loads the config, applies `change` to the entry `id` of `section` in the last config file
/// and checks the result. Writes nothing.
pub fn prepare(
    inputs: &LoadInputs,
    section: Section,
    id: &str,
    change: Change,
) -> Result<Edit, EditError> {
    if !valid_id(id) {
        return Err(EditError::InvalidId(id.to_owned()));
    }
    let current = load(inputs).map_err(EditError::Invalid)?;
    let Some(path) = current.files.last().cloned() else {
        return Err(EditError::NoFile);
    };
    let exists = section.contains(&current.config, id);
    match (&change, exists) {
        (Change::Create(_), true) => {
            return Err(EditError::Exists {
                section,
                id: id.to_owned(),
            });
        }
        (Change::Replace(_) | Change::Remove, false) => {
            return Err(EditError::NotFound {
                section,
                id: id.to_owned(),
            });
        }
        (Change::Replace(_) | Change::Remove, true) => {
            if let Some(origin) = other_source(&current, section, id, &path) {
                return Err(EditError::Conflict {
                    section,
                    id: id.to_owned(),
                    origin,
                    target: path,
                });
            }
        }
        (Change::Create(_), false) => {}
    }
    let parse_error = |message: String| EditError::Parse {
        path: path.clone(),
        message,
    };
    let old_text = std::fs::read_to_string(&path).map_err(|e| parse_error(e.to_string()))?;
    let mut doc = old_text
        .parse::<DocumentMut>()
        .map_err(|e| parse_error(e.to_string()))?;
    apply(&mut doc, section, id, change).map_err(parse_error)?;
    let new_text = doc.to_string();
    let loaded = load_with_file_text(inputs, &path, &new_text).map_err(EditError::Invalid)?;
    Ok(Edit {
        path,
        old_text,
        new_text,
        loaded,
    })
}

/// The first source of a value of the entry that is not the file `target`.
fn other_source(loaded: &Loaded, section: Section, id: &str, target: &Path) -> Option<Source> {
    loaded
        .sources
        .iter()
        .filter(|(key, _)| key.len() >= 2 && key[0] == section.key() && key[1] == id)
        .map(|(_, source)| source)
        .find(|source| !matches!(source, Source::File { path, .. } if path == target))
        .cloned()
}

fn apply(doc: &mut DocumentMut, section: Section, id: &str, change: Change) -> Result<(), String> {
    let root = doc.as_table_mut();
    if !root.contains_key(section.key()) {
        let mut table = Table::new();
        table.set_implicit(true);
        root.insert(section.key(), Item::Table(table));
    }
    let slot = &mut root[section.key()];
    if !slot.is_table() {
        // `user = { ... }` or `user.alice = ...` as a value: turn it into a table so an entry can
        // be a `[user.<id>]` table.
        let item = std::mem::take(slot);
        *slot = Item::Table(
            item.into_table()
                .map_err(|_| format!("`{}` is not a table", section.key()))?,
        );
    }
    let Some(entries) = slot.as_table_mut() else {
        return Err(format!("`{}` is not a table", section.key()));
    };
    match change {
        Change::Remove => {
            entries.remove(id);
        }
        Change::Create(mut table) => {
            if entries.iter().next().is_some() || entries.position().is_some() {
                // Keep a blank line before the new table header.
                table.decor_mut().set_prefix("\n");
            }
            entries.insert(id, Item::Table(table));
        }
        Change::Replace(mut table) => {
            let old = entries.remove(id);
            if let Some(Item::Table(old)) = &old {
                table.set_position(old.position());
                if let Some(prefix) = old.decor().prefix() {
                    table.decor_mut().set_prefix(prefix.clone());
                }
            }
            entries.insert(id, Item::Table(table));
        }
    }
    Ok(())
}

/// Writes `text` to a temporary file in the same directory, then renames it to `path`. The new
/// file keeps the permissions of the old one.
pub fn write_atomic(path: &Path, text: &str) -> std::io::Result<()> {
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let name = path
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    let tmp = dir.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        if let Ok(meta) = std::fs::metadata(path) {
            std::fs::set_permissions(&tmp, meta.permissions())?;
        }
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Converts a JSON value to a TOML value. JSON `null` has no TOML form.
pub fn toml_value(value: &serde_json::Value) -> Result<toml_edit::Value, String> {
    use serde_json::Value as J;
    Ok(match value {
        J::Null => return Err("null is not a valid TOML value".to_owned()),
        J::Bool(b) => (*b).into(),
        J::Number(n) => match (n.as_i64(), n.as_f64()) {
            (Some(i), _) => i.into(),
            (None, Some(f)) => f.into(),
            (None, None) => return Err(format!("number {n} is out of range")),
        },
        J::String(s) => s.as_str().into(),
        J::Array(items) => {
            let mut array = toml_edit::Array::new();
            for item in items {
                array.push(toml_value(item)?);
            }
            toml_edit::Value::Array(array)
        }
        J::Object(map) => toml_edit::Value::InlineTable(inline_table(map)?),
    })
}

/// Converts a JSON object to an inline TOML table.
pub fn inline_table(
    map: &serde_json::Map<String, serde_json::Value>,
) -> Result<toml_edit::InlineTable, String> {
    let mut table = toml_edit::InlineTable::new();
    for (key, value) in map {
        table.insert(key, toml_value(value).map_err(|e| format!("{key}: {e}"))?);
    }
    Ok(table)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_util::*;

    const BASE: &str = "\
# Local issuer.
[issuer.a]
issuer_url = \"http://localhost:9000/a\"

# The admin.
[user.alice]
label = \"Alice\" # keep me
claims = { email = \"alice@example.com\" }
";

    fn file_inputs(text: &str) -> (LoadInputs, PathBuf) {
        let file = write_tmp(text);
        let mut i = inputs(&[]);
        i.config_files = vec![file.clone()];
        (i, file)
    }

    fn table(label: &str) -> Table {
        let mut t = Table::new();
        t.insert("label", toml_edit::value(label));
        t
    }

    #[test]
    fn create_appends_a_table_and_keeps_comments() {
        let (i, file) = file_inputs(BASE);
        let edit = prepare(&i, Section::User, "bob", Change::Create(table("Bob"))).unwrap();
        assert_eq!(
            edit.new_text,
            format!("{BASE}\n[user.bob]\nlabel = \"Bob\"\n"),
            "{}",
            edit.new_text
        );
        assert_eq!(edit.loaded.config.user["bob"].label, "Bob");
        // Nothing is written before `write`.
        assert_eq!(std::fs::read_to_string(&file).unwrap(), BASE);
        edit.write().unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), edit.new_text);
    }

    #[test]
    fn create_in_a_file_without_users() {
        let (i, _) = file_inputs("[issuer.a]\nissuer_url = \"http://localhost:9000/a\"\n");
        let edit = prepare(&i, Section::User, "bob", Change::Create(table("Bob"))).unwrap();
        assert_eq!(
            edit.new_text,
            "[issuer.a]\nissuer_url = \"http://localhost:9000/a\"\n\n[user.bob]\nlabel = \"Bob\"\n"
        );
    }

    #[test]
    fn create_refuses_an_existing_id() {
        let (i, _) = file_inputs(BASE);
        let e = prepare(&i, Section::User, "alice", Change::Create(table("A"))).unwrap_err();
        assert!(matches!(e, EditError::Exists { .. }), "{e}");
        assert_eq!(e.to_string(), "User alice already exists");
    }

    #[test]
    fn replace_keeps_the_position_and_the_comment_above() {
        let text = format!("{BASE}\n[user.bob]\nlabel = \"Bob\"\n");
        let (i, _) = file_inputs(&text);
        let edit = prepare(&i, Section::User, "alice", Change::Replace(table("Al"))).unwrap();
        assert_eq!(
            edit.new_text,
            "# Local issuer.\n[issuer.a]\nissuer_url = \"http://localhost:9000/a\"\n\n\
             # The admin.\n[user.alice]\nlabel = \"Al\"\n\n[user.bob]\nlabel = \"Bob\"\n",
            "{}",
            edit.new_text
        );
        assert!(edit.loaded.config.user["alice"].claims.is_empty());
    }

    #[test]
    fn remove_drops_the_entry_and_its_sub_tables() {
        let text = format!("{BASE}\n[user.alice.issuer.a]\nclaims = {{ sub = \"x\" }}\n");
        let (i, _) = file_inputs(&text);
        let edit = prepare(&i, Section::User, "alice", Change::Remove).unwrap();
        assert!(!edit.new_text.contains("alice"), "{}", edit.new_text);
        assert!(edit.new_text.starts_with("# Local issuer."));
        assert!(edit.loaded.config.user.is_empty());
    }

    #[test]
    fn unknown_id_is_not_found() {
        let (i, _) = file_inputs(BASE);
        for change in [Change::Replace(table("X")), Change::Remove] {
            let e = prepare(&i, Section::User, "zed", change).unwrap_err();
            assert_eq!(e.to_string(), "unknown user: zed");
        }
    }

    #[test]
    fn invalid_id_is_refused() {
        let (i, _) = file_inputs(BASE);
        let e = prepare(&i, Section::User, "Bad-Id", Change::Create(table("X"))).unwrap_err();
        assert!(matches!(e, EditError::InvalidId(_)), "{e}");
    }

    #[test]
    fn no_file_is_refused() {
        let e = prepare(&inputs(&[]), Section::User, "x", Change::Create(table("X"))).unwrap_err();
        assert!(matches!(e, EditError::NoFile), "{e}");
        let i = inputs(&[(
            "FAUXIDC_CONFIG_INLINE",
            "[issuer.a]\nissuer_url = \"http://localhost:9000/a\"",
        )]);
        let e = prepare(&i, Section::User, "x", Change::Create(table("X"))).unwrap_err();
        assert!(matches!(e, EditError::NoFile), "{e}");
    }

    #[test]
    fn writes_go_to_the_last_file_and_refuse_entries_of_other_sources() {
        let first = write_tmp(BASE);
        let last = write_tmp("[user.bob]\nlabel = \"Bob\"\n");
        let mut i = inputs(&[(
            "FAUXIDC__USER__BOB__CLAIMS",
            "{ email = \"b@example.com\" }",
        )]);
        i.config_files = vec![first.clone(), last.clone()];

        let e = prepare(&i, Section::User, "alice", Change::Remove).unwrap_err();
        assert!(matches!(e, EditError::Conflict { .. }), "{e}");
        let message = e.to_string();
        assert!(
            message.starts_with(&format!("User alice is set in {}:", first.display())),
            "{message}"
        );

        let e = prepare(&i, Section::User, "bob", Change::Replace(table("B"))).unwrap_err();
        assert!(
            e.to_string()
                .starts_with("User bob is set in env FAUXIDC__USER__BOB__CLAIMS"),
            "{e}"
        );

        let edit = prepare(&i, Section::User, "carol", Change::Create(table("C"))).unwrap();
        assert_eq!(edit.path, last);
    }

    #[test]
    fn an_invalid_result_is_refused() {
        let (i, file) = file_inputs(BASE);
        let mut bad = table("X");
        bad.insert("nope", toml_edit::value(1));
        let e = prepare(&i, Section::User, "bob", Change::Create(bad)).unwrap_err();
        assert!(e.is_config_error(), "{e}");
        assert!(e.to_string().contains("nope"), "{e}");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), BASE);
    }

    #[test]
    fn an_inline_section_becomes_a_table() {
        let (i, _) = file_inputs(
            "user = { alice = { label = \"A\" } }\n\
             [issuer.a]\nissuer_url = \"http://localhost:9000/a\"\n",
        );
        let edit = prepare(&i, Section::User, "bob", Change::Create(table("Bob"))).unwrap();
        assert_eq!(edit.loaded.config.user.len(), 2, "{}", edit.new_text);
    }

    #[test]
    fn restore_writes_the_old_text() {
        let (i, file) = file_inputs(BASE);
        let edit = prepare(&i, Section::User, "bob", Change::Create(table("Bob"))).unwrap();
        edit.write().unwrap();
        edit.restore().unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), BASE);
    }

    #[test]
    fn json_values_become_toml_values() {
        let json = serde_json::json!({"a": 1, "b": 1.5, "c": [true, "x"], "d": {"e": "f"}});
        let t = inline_table(json.as_object().unwrap()).unwrap();
        assert_eq!(
            t.to_string(),
            "{ a = 1, b = 1.5, c = [true, \"x\"], d = { e = \"f\" } }"
        );
        assert!(toml_value(&serde_json::Value::Null).is_err());
    }
}
