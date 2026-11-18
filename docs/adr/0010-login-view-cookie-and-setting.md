# 10. The login page view: cookie, then Issuer setting, then `false`

Date: 2026-11-17
Status: accepted.

## Context

The login page first showed a User dropdown with a "Custom…" entry. Most visits need a Custom user or a User, and the old dropdown hid the Custom user form behind one entry.
Issue #44 asked for a switch on the login page to choose the view. Issue #45 asked for a setting on the dashboard. A test run needs a way to set the view for every browser, and a person needs the view to stay on reload.

Config has several sources (spec 5.1). Env, inline config and flags change only at restart. ADR 0008 sets how a Test API write changes the config.
The page script writes the cookie, so the cookie cannot be `HttpOnly`.

## Decision

- The page opens on the Custom user form. A switch "Choose a configured User" shows the User dropdown. The dropdown has no Custom user entry.
- The start view is the first rule that applies:
  1. The Issuer has no Users: form.
  2. The `user` field has an error: dropdown.
  3. A rejected form posted a `user`: that view.
  4. A known `login_hint`: dropdown.
  5. The cookie.
  6. The Issuer setting.
- The cookie is `fauxidc_login_view_{issuer_id}`, with the value `list` or `form`. `Path` is the Issuer path, `SameSite=Lax`, `Max-Age=31536000`.
  It is not `HttpOnly`, because the page script writes it. Any other value is ignored. `{issuer}/endsession` clears it.
- The Issuer setting is `issuer.<id>.show_user_list`. The default is `false`.
- `PUT /_mock/{issuer-id}/login` and the dashboard switch write the key to the last config file (ADR 0008).
  With no config file, or a read-only one (issue #59), the value stays in memory. A hot reload keeps it. `DELETE /_mock/state` and a restart clear it.
- With a config file, a write fails with 409 when an env var, inline config or a flag sets the key. Without a config file, the value goes to memory and overrides the env value. The answer of `GET` has the `source`: `default`, `file`, `memory`, `env`, `inline`, `flag` or `unknown`.
- The Config view shows a memory value with the source `memory`.
- The login template context has version 3 with the new fields `show_user_list`, `user_list_saved`, `view_cookie` and `view_cookie_path`.

## Rejected options

- Keep the setting in memory only (the first idea in #45): it is lost at restart, and a person cannot see it in the config file.
- Make the cookie `HttpOnly`: the page script could not write it, so the server would need a route for each switch.
- Make the Issuer setting win over the cookie: a person who chose a view would lose it at the next visit.

## Consequences

- The default view changes from the User dropdown to the Custom user form. A test that picks a User must click the switch or set `show_user_list = true`.
- A custom login template that reads `custom_label` or posts `user=__custom__` keeps working. The built-in page no longer shows the label.
- Each Issuer has its own cookie and its own setting.
- A Test API write can change a config file, the same as ADR 0008.
