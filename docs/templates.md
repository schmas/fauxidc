# Templates

fauxidc renders four pages with [minijinja](https://docs.rs/minijinja) (Jinja syntax, HTML autoescape on):
`login.html`, `error.html`, `signed_out.html` and `debugger.html`. The embedded defaults live in `assets/templates/`.

## Overrides

- `server.templates_dir`: a file named `login.html`, `error.html`, `signed_out.html` or `debugger.html` in this directory replaces the embedded one.
- `issuer.<id>.login_template`: a file path. It replaces the login page for that issuer only.
- `server.static_dir`: files here take precedence over the embedded static files, served at `/_mock/static/<path>`.

A missing `login_template` file or a template syntax error stops the server at startup.

## Context version 1

Every context has `context_version` (integer, `1`). Fields are added in a minor release only if they are optional for existing templates. Removing or renaming a field is a breaking release.

The autoescape writes `/` as `&#x2f;`, which a browser decodes. The `href` filter escapes like the autoescape but keeps `/`, for readable links: `<a href="{{ change_href|href }}">`.

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
| `remember` | boolean | `true` to render the `remember` checkbox checked, for example after a form error. |
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

### `signed_out.html`

`/endsession` renders this page when the request has no `post_logout_redirect_uri`. It is a new, optional template: existing `templates_dir` overrides keep working, and the context version stays `1`.

| Field | Type | Meaning |
| --- | --- | --- |
| `context_version` | integer | Always `1`. |
| `issuer_id` | string | Id of the issuer. |
| `client_id` | string or null | The Client of the logout request, from `client_id` or `id_token_hint`, when known. |
| `signed_in_as` | string or null | The label (or id) of the Auto-select User, when the request cookie names a configured User. |
| `change_href` | string or null | The debugger `?forget=1` URL of the Issuer. It clears the Auto-select cookie. |
| `static_base` | string | URL prefix for static files, `/_mock/static`. |

`signed_in_as` and `change_href` are new optional fields. The default page shows `Signed in as <label> · change`.

### `debugger.html`

`GET {debugger}` (default path `/debugger`) renders this page. `POST {debugger}` with the form field `token` renders it with the decoded token.
The login flow callback renders it with the decoded tokens of the flow. It is a new, optional template.

| Field | Type | Meaning |
| --- | --- | --- |
| `context_version` | integer | Always `1`. |
| `issuer_id` | string | Id of the issuer. |
| `action` | string | The debugger path. Post the form here with `method="post"` and a field `token`. |
| `start_href` | string | `action` + `/start`. A link here starts the login flow with the built-in `debugger` Client. |
| `token` | string | The pasted value, to keep in the textarea. |
| `decoded` | decoded JWT or null | The pasted token, decoded. |
| `flow` | list of `[name, decoded JWT]` | The tokens of a finished login flow: `id_token`, `access_token`, `refresh_token` (when present). |
| `flow_raw` | string or null | The token response of a finished login flow, as pretty JSON. |
| `error` | string or null | An error message, for example `not a JWT: …` or an error of the login flow. |
| `signed_in_as` | string or null | As on `signed_out.html`. |
| `change_href` | string | `action` + `?forget=1`. |
| `static_base` | string | URL prefix for static files, `/_mock/static`. |

A decoded JWT has these fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `header` | string | The header as pretty JSON. |
| `payload` | string | The payload as pretty JSON. |
| `signature_valid` | boolean | `true` when a key of this Issuer (by `kid`) verifies the signature. |
| `signature_note` | string | `valid (kid <kid>, <alg>)`, or the reason the check failed. |
| `expiry_note` | string | `exp <n>: expires in <s> s`, `exp <n>: expired <s> s ago`, or `no exp`. |
