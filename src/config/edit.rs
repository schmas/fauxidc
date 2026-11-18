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
//! 5. [`Edit::write`] writes the new text atomically: a temporary file, then a rename. A
//!    Docker single-file mount refuses the rename; the text then goes into the file in place.

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
    /// `[issuer.<id>]`
    Issuer,
}

impl Section {
    /// The top-level config key.
    pub fn key(self) -> &'static str {
        match self {
            Section::User => "user",
            Section::Client => "client",
            Section::Issuer => "issuer",
        }
    }

    /// The glossary term, for messages.
    pub fn noun(self) -> &'static str {
        match self {
            Section::User => "User",
            Section::Client => "Client",
            Section::Issuer => "Issuer",
        }
    }

    fn contains(self, config: &Config, id: &str) -> bool {
        match self {
            Section::User => config.user.contains_key(id),
            Section::Client => config.client.contains_key(id),
            Section::Issuer => config.issuer.contains_key(id),
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
    edit_file(inputs, path, |doc| apply(doc, section, id, change))
}

/// Reads the target file, changes its document with `mutate`, and loads the config with the new
/// text.
fn edit_file(
    inputs: &LoadInputs,
    path: PathBuf,
    mutate: impl FnOnce(&mut DocumentMut) -> Result<(), String>,
) -> Result<Edit, EditError> {
    let parse_error = |message: String| EditError::Parse {
        path: path.clone(),
        message,
    };
    let old_text = std::fs::read_to_string(&path).map_err(|e| parse_error(e.to_string()))?;
    let mut doc = old_text
        .parse::<DocumentMut>()
        .map_err(|e| parse_error(e.to_string()))?;
    mutate(&mut doc).map_err(parse_error)?;
    let new_text = doc.to_string();
    let loaded = load_with_file_text(inputs, &path, &new_text).map_err(EditError::Invalid)?;
    Ok(Edit {
        path,
        old_text,
        new_text,
        loaded,
    })
}

/// Sets the boolean `issuer.<issuer_id>.<key>` in the last config file and checks the result.
/// Writes nothing.
///
/// A value from an earlier file is not a conflict: the last file wins the merge. A value from
/// env, inline config or a flag is a conflict: a file write would not win.
pub fn prepare_issuer_bool(
    inputs: &LoadInputs,
    issuer_id: &str,
    key: &str,
    value: bool,
) -> Result<Edit, EditError> {
    let section = Section::Issuer;
    if !valid_id(issuer_id) {
        return Err(EditError::InvalidId(issuer_id.to_owned()));
    }
    let current = load(inputs).map_err(EditError::Invalid)?;
    let Some(path) = current.files.last().cloned() else {
        return Err(EditError::NoFile);
    };
    if !section.contains(&current.config, issuer_id) {
        return Err(EditError::NotFound {
            section,
            id: issuer_id.to_owned(),
        });
    }
    let source_key = vec![
        section.key().to_owned(),
        issuer_id.to_owned(),
        key.to_owned(),
    ];
    if let Some(origin) = current
        .sources
        .get(&source_key)
        .filter(|source| !matches!(source, Source::File { .. }))
    {
        return Err(EditError::Conflict {
            section,
            id: issuer_id.to_owned(),
            origin: origin.clone(),
            target: path,
        });
    }
    edit_file(inputs, path, |doc| {
        set_issuer_bool(doc, issuer_id, key, value)
    })
}

fn set_issuer_bool(
    doc: &mut DocumentMut,
    issuer_id: &str,
    key: &str,
    value: bool,
) -> Result<(), String> {
    let issuers = section_table(doc, Section::Issuer.key())?;
    if let Some(entry) = issuers.get_mut(issuer_id) {
        if !entry.is_table() {
            let item = std::mem::take(entry);
            *entry = Item::Table(
                item.into_table()
                    .map_err(|_| format!("`issuer.{issuer_id}` is not a table"))?,
            );
        }
        let Some(table) = entry.as_table_mut() else {
            return Err(format!("`issuer.{issuer_id}` is not a table"));
        };
        table.insert(key, toml_edit::value(value));
    } else {
        let mut table = Table::new();
        if issuers.iter().next().is_some() || issuers.position().is_some() {
            // Keep a blank line before the new table header.
            table.decor_mut().set_prefix("\n");
        }
        table.insert(key, toml_edit::value(value));
        issuers.insert(issuer_id, Item::Table(table));
    }
    Ok(())
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

/// The top-level table `key`. It creates an implicit table when missing, and turns an inline
/// value (`user = { ... }`) into a table, so an entry can be a `[user.<id>]` table.
fn section_table<'a>(doc: &'a mut DocumentMut, key: &str) -> Result<&'a mut Table, String> {
    let root = doc.as_table_mut();
    if !root.contains_key(key) {
        let mut table = Table::new();
        table.set_implicit(true);
        root.insert(key, Item::Table(table));
    }
    let slot = &mut root[key];
    if !slot.is_table() {
        let item = std::mem::take(slot);
        *slot = Item::Table(
            item.into_table()
                .map_err(|_| format!("`{key}` is not a table"))?,
        );
    }
    slot.as_table_mut()
        .ok_or_else(|| format!("`{key}` is not a table"))
}

fn apply(doc: &mut DocumentMut, section: Section, id: &str, change: Change) -> Result<(), String> {
    let entries = section_table(doc, section.key())?;
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
///
/// A file without write permission is read-only: the write is refused before the temporary
/// file, also for root. [`is_read_only`] is `true` for the error.
///
/// If the rename fails with `EBUSY` or `EXDEV`, the text goes into `path` in place. Docker
/// mounts a single config file (`-v ./fauxidc.toml:/config/fauxidc.toml`) as a mount point,
/// and Linux refuses a rename onto a mount point with `EBUSY`. `EXDEV` is a rename across file
/// systems. The in-place write is not atomic, but it is the only write that such a mount
/// accepts. If the temporary file cannot be created (a read-only or not writable directory),
/// the text also goes into `path` in place.
pub fn write_atomic(path: &Path, text: &str) -> std::io::Result<()> {
    write_with_rename(path, text, |from, to| std::fs::rename(from, to))
}

/// [`write_atomic`] with the rename step as a parameter, so a test can make it fail.
fn write_with_rename(
    path: &Path,
    text: &str,
    rename: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let old = std::fs::metadata(path).ok();
    if old
        .as_ref()
        .is_some_and(|meta| meta.permissions().readonly())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "the file is read-only",
        ));
    }
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let name = path
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    let tmp = dir.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4()));
    let mut file = match std::fs::File::create(&tmp) {
        Ok(file) => file,
        Err(e) if old.is_some() && is_read_only(&e) => return write_in_place(path, text),
        Err(e) => return Err(e),
    };
    let result = (|| {
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        drop(file);
        if let Some(meta) = &old {
            std::fs::set_permissions(&tmp, meta.permissions())?;
        }
        rename(&tmp, path)
    })();
    match result {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            if old.is_some()
                && matches!(
                    e.kind(),
                    std::io::ErrorKind::ResourceBusy | std::io::ErrorKind::CrossesDevices
                )
            {
                write_in_place(path, text)
            } else {
                Err(e)
            }
        }
    }
}

/// Writes `text` into the existing file `path`: truncate, write, sync. The file keeps its
/// inode, owner and permissions.
fn write_in_place(path: &Path, text: &str) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()
}

/// `true` when a write failed because the file or its file system is read-only: `EROFS` (for
/// example a `:ro` mount) or `EACCES`.
#[must_use]
pub fn is_read_only(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ReadOnlyFilesystem | std::io::ErrorKind::PermissionDenied
    )
}

/// `true` when the existing file `path` cannot be written: it has no write permission, or an
/// open for writing fails as read-only. The check does not change the file.
#[must_use]
pub fn file_is_read_only(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(meta) if meta.permissions().readonly() => true,
        Ok(_) => std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .is_err_and(|e| is_read_only(&e)),
        Err(_) => false,
    }
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

    /// A file `fauxidc.toml` with `text` in a new empty directory.
    fn file_in_dir(text: &str) -> (PathBuf, PathBuf) {
        let dir = empty_tmp_dir();
        let file = dir.join("fauxidc.toml");
        std::fs::write(&file, text).unwrap();
        (dir, file)
    }

    fn names_in(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    /// Docker refuses a rename onto a single-file bind mount (`EBUSY`), and a rename across
    /// file systems fails with `EXDEV`. The write then goes into the file in place.
    #[test]
    fn a_busy_or_cross_device_rename_writes_the_file_in_place() {
        for kind in [
            std::io::ErrorKind::ResourceBusy,
            std::io::ErrorKind::CrossesDevices,
        ] {
            let (dir, file) =
                file_in_dir("old = 1\n# a long old line that the new text is shorter than\n");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
            }
            write_with_rename(&file, "new = 2\n", |_, _| Err(std::io::Error::from(kind))).unwrap();
            assert_eq!(
                std::fs::read_to_string(&file).unwrap(),
                "new = 2\n",
                "{kind:?}"
            );
            assert_eq!(names_in(&dir), vec!["fauxidc.toml".to_owned()], "{kind:?}");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&file).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o640, "{kind:?}");
            }
        }
    }

    #[test]
    fn another_rename_error_fails_and_keeps_the_file() {
        let (dir, file) = file_in_dir("old = 1\n");
        let e = write_with_rename(&file, "new = 2\n", |_, _| {
            Err(std::io::Error::other("no rename"))
        })
        .unwrap_err();
        assert_eq!(e.to_string(), "no rename");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "old = 1\n");
        assert_eq!(names_in(&dir), vec!["fauxidc.toml".to_owned()]);
    }

    /// A file without write permission is read-only, also for root: the write is refused
    /// before the temporary file.
    #[test]
    fn a_read_only_file_is_refused() {
        let (dir, file) = file_in_dir("old = 1\n");
        let mut permissions = std::fs::metadata(&file).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&file, permissions).unwrap();
        assert!(file_is_read_only(&file));
        let e = write_atomic(&file, "new = 2\n").unwrap_err();
        assert!(is_read_only(&e), "{e:?}");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "old = 1\n");
        assert_eq!(names_in(&dir), vec!["fauxidc.toml".to_owned()]);
    }

    /// A directory without write permission refuses the temporary file. A writable file in it
    /// is written in place. Root can write any directory, so the test checks nothing as root.
    #[cfg(unix)]
    #[test]
    fn a_read_only_directory_writes_the_file_in_place() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, file) = file_in_dir("old = 1\n");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let probe = dir.join("probe");
        if std::fs::write(&probe, "").is_ok() {
            let _ = std::fs::remove_file(&probe);
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            return;
        }
        let result = write_atomic(&file, "new = 2\n");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        result.unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "new = 2\n");
        assert_eq!(names_in(&dir), vec!["fauxidc.toml".to_owned()]);
    }

    #[test]
    fn read_only_errors() {
        use std::io::{Error, ErrorKind};
        assert!(is_read_only(&Error::from(ErrorKind::ReadOnlyFilesystem)));
        assert!(is_read_only(&Error::from(ErrorKind::PermissionDenied)));
        assert!(!is_read_only(&Error::from(ErrorKind::ResourceBusy)));
        let (_, file) = file_in_dir("old = 1\n");
        assert!(!file_is_read_only(&file));
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

    #[test]
    fn issuer_bool_sets_the_key_and_keeps_comments() {
        let (i, _) = file_inputs(BASE);
        let edit = prepare_issuer_bool(&i, "a", "show_user_list", true).unwrap();
        assert!(
            edit.new_text.contains(
                "# Local issuer.\n[issuer.a]\nissuer_url = \"http://localhost:9000/a\"\nshow_user_list = true\n"
            ),
            "{}",
            edit.new_text
        );
        assert!(edit.new_text.contains("label = \"Alice\" # keep me"));
        assert!(edit.loaded.config.issuer["a"].show_user_list);
        let (i2, _) = file_inputs(&edit.new_text);
        let edit = prepare_issuer_bool(&i2, "a", "show_user_list", false).unwrap();
        assert_eq!(edit.new_text.matches("show_user_list").count(), 1);
        assert!(edit.new_text.contains("show_user_list = false"));
        assert!(!edit.loaded.config.issuer["a"].show_user_list);
    }

    #[test]
    fn issuer_bool_from_an_earlier_file_adds_a_table() {
        let first = write_tmp("[issuer.a]\nissuer_url = \"http://localhost:9000/a\"\n");
        let last = write_tmp("[user.bob]\nlabel = \"Bob\"\n");
        let mut i = inputs(&[]);
        i.config_files = vec![first, last.clone()];
        let edit = prepare_issuer_bool(&i, "a", "show_user_list", true).unwrap();
        assert_eq!(edit.path, last);
        assert!(
            edit.new_text.contains("[issuer.a]\nshow_user_list = true"),
            "{}",
            edit.new_text
        );
        let issuer = &edit.loaded.config.issuer["a"];
        assert!(issuer.show_user_list);
        assert_eq!(issuer.issuer_url, "http://localhost:9000/a");
    }

    #[test]
    fn issuer_bool_refuses_env() {
        let file = write_tmp(BASE);
        let mut i = inputs(&[("FAUXIDC__ISSUER__A__SHOW_USER_LIST", "true")]);
        i.config_files = vec![file];
        let e = prepare_issuer_bool(&i, "a", "show_user_list", false).unwrap_err();
        assert!(
            matches!(
                e,
                EditError::Conflict {
                    section: Section::Issuer,
                    ..
                }
            ),
            "{e}"
        );
    }

    #[test]
    fn issuer_bool_unknown_issuer_and_no_file() {
        let (i, _) = file_inputs(BASE);
        let e = prepare_issuer_bool(&i, "zed", "show_user_list", true).unwrap_err();
        assert!(
            matches!(
                e,
                EditError::NotFound {
                    section: Section::Issuer,
                    ..
                }
            ),
            "{e}"
        );
        let e = prepare_issuer_bool(&inputs(&[]), "default", "show_user_list", true).unwrap_err();
        assert!(matches!(e, EditError::NoFile), "{e}");
    }
}
