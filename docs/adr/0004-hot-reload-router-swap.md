# 4. Hot reload swaps the whole router

Date: 2026-11-14
Status: accepted

## Context

M3 adds hot reload (spec 11). The mock polls the config files and also reloads on SIGHUP.
If the new config is invalid, the mock keeps the old one. In-flight codes, Sessions and refresh tokens stay valid.

The config shapes the routes: each Issuer has its own path, and `paths` can move each endpoint.
Discovery, CORS origins and templates also come from the config.
Up to M2, the router and the CORS layers are built once at startup.

## Decision

- Each reload builds a new version of the app: a new `AppState` (config, templates) and a new `Router` from `build_router`.
- `arc-swap` holds the current router and state. The served router has only a fallback. It loads the current router and calls it with `oneshot`.
- A request runs entirely on the version that it started with. A reload never changes a request in progress.
- The `Store`, the `Keyring` and the `RequestLog` are shared by all versions. So codes, Sessions, used refresh `jti`s, revocations, Injected failures, debugger flows and Lenient registrations survive a reload. A Lenient registration is used only while its Issuer is Lenient. If a reload switches the Issuer to Strict, the registration stays in the Store but `find_client` ignores it.
- A reload validates the new config and loads its templates before the swap. On any error nothing changes.
- A file change applies after two equal polls: the poller applies new file stamps only when two polls in a row see them, so a half-written file is not applied.
- Keys that need a restart keep their running values in the new config, and the mock logs a warning: `server.port`, `server.bind`, `server.log_format`, `server.request_log_size`, `server.key_file`, `server.tls`, `issuer.<id>.signing_alg`, `issuer.<id>.key_file`.
- An Issuer added by a reload gets a key as at startup. The key slot of a removed Issuer stays, so its keys come back if it is added again.

## Rejected option

One long-lived router that reads an `ArcSwap<Config>` in every handler.
The routes depend on the config (Issuer paths and `paths` overrides).
So this option needs a hand-written dispatcher in place of the axum router, and the CORS layers must read the config per request.

## Consequences

- Routes, `paths`, discovery, CORS origins, templates and `login_template` files all follow a reload.
- A reload costs one router build. This is small next to a file poll every second.
- The restart-only keys have no effect until restart. The listener, the logger, the Request log buffer and the keys already exist.
- Env and inline config values come from the startup snapshot. They change only at restart.
