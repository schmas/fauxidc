# Templates

fauxidc renders two pages with [minijinja](https://docs.rs/minijinja) (Jinja syntax, HTML autoescape on):
`login.html` and `error.html`. The embedded defaults live in `assets/templates/`.

## Overrides

- `server.templates_dir`: a file named `login.html` or `error.html` in this directory replaces the embedded one.
- `issuer.<id>.login_template`: a file path. It replaces the login page for that issuer only.
- `server.static_dir`: files here take precedence over the embedded static files, served at `/_mock/static/<path>`.

A missing `login_template` file or a template syntax error stops the server at startup.

## Context version 1

Every context has `context_version` (integer, `1`). Fields are added in a minor release only if they are optional for existing templates. Removing or renaming a field is a breaking release.

### `login.html` and `issuer.<id>.login_template`

| Field | Type | Meaning |
| --- | --- | --- |
| `context_version` | integer | Always `1`. |
| `issuer_id` | string | Id of the issuer. |
| `client_id` | string | The `client_id` of the authorize request. |
| `action` | string | The form target. Post the form here with `method="post"`. |
| `users` | list of `{id, label}` | The configured users. `label` is the user label, or the id when there is no label. |
| `selected` | string or null | The `id` of the user to preselect, or `__custom__`. |
| `params` | list of `[name, value]` | The authorize request parameters. |
| `error` | string or null | An error message to show above the form. |
| `custom_sub` | string | Prefilled text for the custom subject. |
| `custom_claims` | string | Prefilled JSON text for the custom claims. |
| `override_claims` | string | Prefilled JSON text for the override claims. |
| `static_base` | string | URL prefix for static files, `/_mock/static`. |

`params` must be posted back unchanged: render each pair as `<input type="hidden" name="{{ pair[0] }}" value="{{ pair[1] }}">`.

The form fields the server reads: `user` (a user `id` or `__custom__`), `custom_sub`, `custom_claims`, `override_claims`, and `remember` (checkbox). The flow needs no JavaScript.

### `error.html`

| Field | Type | Meaning |
| --- | --- | --- |
| `context_version` | integer | Always `1`. |
| `issuer_id` | string | Id of the issuer. |
| `message` | string | The error message. |
| `static_base` | string | URL prefix for static files, `/_mock/static`. |
