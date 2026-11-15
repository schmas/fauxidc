# Templates

fauxidc renders four pages with [minijinja](https://docs.rs/minijinja) (Jinja syntax, HTML autoescape on):
`login.html`, `error.html`, `signed_out.html` and `debugger.html`. The embedded defaults live in `assets/templates/`.

## Overrides

- `server.templates_dir`: a file named `login.html`, `error.html`, `signed_out.html` or `debugger.html` in this directory replaces the embedded one.
- `issuer.<id>.login_template`: a file path. It replaces the login page for that issuer only.
- `server.static_dir`: files here take precedence over the embedded static files, served at `/_mock/static/<path>`.

A missing `login_template` file or a template syntax error stops the server at startup.

## Styles

The built-in pages link one stylesheet, `/_mock/static/fauxidc.css` (`{{ static_base|href }}/fauxidc.css` in a template).
It is compiled at dev time with Tailwind CSS v4 and daisyUI v5 and embedded in the binary. The page needs no network.
Light and dark themes follow the browser `prefers-color-scheme` setting.

A custom template (`templates_dir` or `login_template`) can link the same file and use the classes that the built-in templates use.
The compiled file has only those classes: it is built from `assets/templates/`, so another Tailwind or daisyUI class has no style.
For other styles, put your own file in `server.static_dir` and link it.

`/_mock/static/login.css`, the stylesheet of the old built-in pages, is still served, so old templates that link it keep working.

## Context version 2

Every context has `context_version` (integer, `2`). Fields are added in a minor release only if they are optional for existing templates. Removing or renaming a field is a breaking release.

### Changes from version 1

- `context_version` is `2` in all four contexts. A template that tests `context_version == 1` must change.
- `login.html`: new fields `custom_label`, `custom_username`, `username` and `error_field`.
- `login.html`: new form field `username`, read when the Issuer has `custom_user`.
- `debugger.html`: a decoded JWT has the new field `issuer_note`.
- `signed_out.html`: `signed_in_as` is always null.

No field is removed or renamed.

The autoescape writes `/` as `&#x2f;`, which a browser decodes. The `href` filter escapes like the autoescape but keeps `/`, for readable links: `<a href="{{ change_href|href }}">`.

### `login.html` and `issuer.<id>.login_template`

| Field | Type | Meaning |
| --- | --- | --- |
| `context_version` | integer | Always `2`. |
| `issuer_id` | string | Id of the issuer. |
| `client_id` | string | The `client_id` of the authorize request. |
| `action` | string | The form target. Post the form here with `method="post"`. |
| `users` | list of `{id, label}` | The configured users. `label` is the user label, or the id when there is no label. |
| `selected` | string or null | The `id` of the user to preselect, or `__custom__`. |
| `params` | list of `[name, value]` | The authorize request parameters. |
| `error` | string or null | An error message to show above the form. |
| `error_field` | string or null | The form field that `error` is about: `user`, `username`, `custom_sub`, `custom_claims` or `override_claims`. Null when there is no error. (Version 2.) |
| `custom_sub` | string | Prefilled text for the custom subject. |
| `custom_claims` | string | Prefilled JSON text for the custom claims. |
| `override_claims` | string | Prefilled JSON text for the override claims. |
| `remember` | boolean | `true` to render the `remember` checkbox checked, for example after a form error. |
| `static_base` | string | URL prefix for static files, `/_mock/static`. |
| `custom_label` | string | The text of the Custom user option: `issuer.<id>.custom_user.label`, else `Custom…`. (Version 2.) |
| `custom_username` | boolean | `true` when the Issuer has `custom_user`. Then show one `username` field instead of `custom_sub` and `custom_claims`. (Version 2.) |
| `username` | string | Prefilled text for the `username` field, for example after a form error. (Version 2.) |

`params` must be posted back unchanged: render each pair as `<input type="hidden" name="{{ pair[0] }}" value="{{ pair[1] }}">`.

The form fields the server reads: `user` (a user `id` or `__custom__`), `custom_sub`, `custom_claims`, `override_claims`, `username`, and `remember` (checkbox). The flow needs no JavaScript.

With `user=__custom__`, the server reads only `username` and `override_claims` when the Issuer has `custom_user`, and only `custom_sub`, `custom_claims` and `override_claims` when it does not.
An empty `username` (after trim) gives the page again with status 400, the error `Enter a username` and `error_field` = `username`.

How `override_claims` applies to a Custom user:

- Subject mode (no `custom_user`): `override_claims` is checked (it must be a JSON object) but not applied. Put the claims in `custom_claims`.
- Username mode (the Issuer has `custom_user`): `override_claims` is merged on top of the template claims (top-level keys, the override wins).
  A `sub` key in `override_claims` changes `sub` too, as a `sub` key in `custom_claims` does in subject mode.

If the Issuer has `custom_user`, a custom `login.html` must render the `username` field when `custom_username` is `true`.
Else the Custom user cannot sign in: the server reads only `username`, and an empty `username` gives the page again with `Enter a username`.

Use `error_field` to mark the failed input, for example with `aria-invalid="true"` and the `input-error`, `textarea-error` or `select-error` class.
The built-in page marks only that input.

### `error.html`

| Field | Type | Meaning |
| --- | --- | --- |
| `context_version` | integer | Always `2`. |
| `issuer_id` | string | Id of the issuer. |
| `message` | string | The error message. |
| `static_base` | string | URL prefix for static files, `/_mock/static`. |

### `signed_out.html`

`/endsession` renders this page when the request has no `post_logout_redirect_uri`. It is an optional template: existing `templates_dir` overrides keep working.

| Field | Type | Meaning |
| --- | --- | --- |
| `context_version` | integer | Always `2`. |
| `issuer_id` | string | Id of the issuer. |
| `client_id` | string or null | The Client of the logout request, from `client_id` or `id_token_hint`, when known. |
| `signed_in_as` | string or null | Always null: the same response clears the Auto-select cookie. The field stays for compatibility. |
| `change_href` | string or null | The debugger `?forget=1` URL of the Issuer. It clears the Auto-select cookie. |
| `static_base` | string | URL prefix for static files, `/_mock/static`. |

`signed_in_as` and `change_href` are optional fields. `signed_in_as` on `signed_out.html` is always null.

### `debugger.html`

`GET {debugger}` (default path `/debugger`) renders this page. `POST {debugger}` with the form field `token` renders it with the decoded token.
The login flow callback renders it with the decoded tokens of the flow. It is a new, optional template.

| Field | Type | Meaning |
| --- | --- | --- |
| `context_version` | integer | Always `2`. |
| `issuer_id` | string | Id of the issuer. |
| `action` | string | The debugger path. Post the form here with `method="post"` and a field `token`. |
| `start_href` | string | `action` + `/start`. A link here starts the login flow with the built-in `debugger` Client. |
| `token` | string | The pasted value, to keep in the textarea. |
| `decoded` | decoded JWT or null | The pasted token, decoded. |
| `flow` | list of `[name, decoded JWT]` | The tokens of a finished login flow: `id_token`, `access_token`, `refresh_token` (when present). |
| `flow_raw` | string or null | The token response of a finished login flow, as pretty JSON. |
| `error` | string or null | An error message, for example `not a JWT: …` or an error of the login flow. |
| `signed_in_as` | string or null | The label (or id) of the Auto-select User, when the request cookie names a configured User. |
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
| `issuer_note` | string | `iss matches this Issuer`, `iss <value> is not this Issuer (<issuer_url>)`, or `no iss`. An exact string comparison. |
