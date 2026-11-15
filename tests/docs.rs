//! Checks that the docs state what users need to know.

use std::path::Path;

/// Reads a repo file, relative to the crate root.
pub fn read(path: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .unwrap_or_else(|e| panic!("cannot read {path}: {e}"))
}

#[test]
fn readme_documents_sessions() {
    let r = read("README.md");
    assert!(r.contains("## Sessions"));
    for needle in [
        "fauxidc_session_",
        "prompt=none",
        "login_required",
        "max_age=0",
        "Auto-select",
        "/endsession",
    ] {
        assert!(r.contains(needle), "{needle}");
    }
    assert!(r.contains("closing the terminal does not stop"));
    assert!(r.contains("/debugger/callback` in `redirect_uris`"));
}

#[test]
fn readme_describes_the_reload_debounce() {
    let r = read("README.md");
    assert!(r.contains("two polls"));
    assert!(r.contains("1 to 2 s after the save"));
    assert!(!r.contains("within about 1 s"));
}
