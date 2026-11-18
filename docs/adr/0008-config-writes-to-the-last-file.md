# 8. Test API and CLI writes go to the last config file

Date: 2026-11-16
Status: accepted.

## Context

Issue #26 adds Test API routes and CLI commands that list, create, change and remove Users. Issue #27 does the same for Clients.
A change must survive a restart and must show on the login page, in `/userinfo` and in the next flow.

Config has several sources (spec 5.1): files deep-merged in order, `FAUXIDC_CONFIG_INLINE` and `FAUXIDC__*` env vars.
Env and inline config change only at restart. A later source wins over a file.
The `toml` crate drops comments and formatting when it writes a document.

## Decision

- A write changes the last config file: the last `--config` file, else the last `FAUXIDC_CONFIG` file, else `./fauxidc.toml`.
  With no file (Zero config, inline config or env vars only), a write fails: 409 on the Test API, exit code 1 on the CLI.
- A write to an existing entry fails when any value of the entry comes from another source: an earlier file, inline config or an env var.
  The error names that source (from the source map, spec 5.8). A write to the last file would not replace those values.
- `toml_edit` changes the file text, so comments and formatting stay. A new entry is a `[user.<id>]` table at the end of the section.
  A replaced entry keeps its place and the comment above it.
- The config is loaded again with the new text before the file changes. On any error the file does not change.
- The file is written atomically: a temporary file in the same directory, then a rename. It keeps the file permissions.
  Issue #59: Linux refuses a rename onto a Docker single-file mount (`EBUSY`). On `EBUSY` or `EXDEV`, the text goes into the file in place.
- On the server, a write applies the new config at once through `ReloadHandle::apply`. It does not wait for the file poller.
  If the apply fails, the old file text is written back. Writes run one at a time.
  The new config becomes the last loaded config, so the next poll sees no change.
- The CLI writes the file and needs no running server. A running server applies the change with its file poller.
- One module (`config::edit`) holds the steps above. The Test API, the CLI, and Clients in #27 use it.
- The write routes reject a cross-origin browser request (403), the same as `rotate-key`.
- A server started with the library API (`Server::start`) has no load inputs, so its write routes answer 409.
  `StartOptions::load_inputs` gives them.

## Rejected options

- Keep Test API changes in memory only: they are lost at restart, and a poll of a changed file would drop them.
- Write a separate overlay file: a new config source that `fauxidc config` and the reload must know about.
- Write to the first file: a later file can override the change, so it may not show.

## Consequences

- New dependency `toml_edit`. It shares `toml_parser`, `toml_writer` and `toml_datetime` with `toml`.
- A comment inside a replaced or removed entry is lost. Comments outside it stay.
- A User that is split across two files must be changed by hand.
- An in-place write (issue #59) is not atomic. A crash during the write can leave a partial file.
- A read-only file (no write permission, or a `:ro` mount) is never changed. User and Client writes give 409.
  The login page setting stays in memory (ADR 0010).
- `StartOptions` has a new field. Code that builds it with a struct literal needs `..Default::default()`.
