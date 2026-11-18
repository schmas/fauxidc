# Templates

fauxidc renders six pages with [minijinja](https://docs.rs/minijinja) (Jinja syntax, HTML autoescape on):
`login.html`, `error.html`, `signed_out.html`, `debugger.html`, `form_post.html` and `dashboard.html`. The embedded defaults live in `assets/templates/`.

## Overrides

- `server.templates_dir`: a file named `login.html`, `error.html`, `signed_out.html`, `debugger.html`, `form_post.html` or `dashboard.html` in this directory replaces the embedded one.
- `issuer.<id>.login_template`: a file path. It replaces the login page for that issuer only.
- `server.static_dir`: files here take precedence over the embedded static files, served at `/_mock/static/<path>`.

A missing `login_template` file or a template syntax error stops the server at startup.

## Styles

Every built-in page links `/_mock/static/halo.css` (`{{ static_base|href }}/halo.css` in a template).
It is plain CSS without a build step, embedded in the binary. The page needs no network.
Light and dark themes follow the browser `prefers-color-scheme` setting. The design file is kept outside the repository.
The dashboard also links `/_mock/static/dashboard.css`, its shell (sidebar and views). It uses the halo tokens.

A custom template (`templates_dir` or `login_template`) can link `halo.css` and use its classes. The main ones:

| Class | Use |
| --- | --- |
| `page`, `page-wide`, `page-top`, `page-foot`, `brand` | The page layout: a centered column, the brand row and the footer. |
| `page-embed` | The page without its outer spacing, for a page in a frame. |
| `card`, `card-head`, `stack`, `row`, `row-between` | Blocks and their spacing. |
| `btn`, `btn-outline`, `select`, `input`, `textarea`, `checkbox`, `field` | Form controls. |
| `input-error`, `select-error`, `textarea-error` | A control with an error. |
| `alert`, `alert-error`, `label`, `label-pair`, `label-success`, `label-warning`, `label-error` | Messages and badges. |
| `table-wrap`, `table-kv`, `code`, `details`, `muted`, `small`, `mono`, `wrap` | Tables, code blocks and text. |

For other styles, put your own file in `server.static_dir` and link it. A file there with the same name replaces the embedded one,
so `server.static_dir` can replace `halo.css` for every page.

`/_mock/static/fauxidc.css` (the Tailwind and daisyUI file of the version 0.4 pages) and `/_mock/static/login.css` (the stylesheet of older pages)
are still served, so old templates that link them keep working. No built-in page links them, and they get no new classes.

## Framing

The pages of an Issuer (`login.html`, `error.html`, `signed_out.html`, `form_post.html`, `debugger.html`) have
`X-Frame-Options: SAMEORIGIN` and `Content-Security-Policy: frame-ancestors 'self'`.
Only a page of the same origin, the dashboard Debugger view, can show them in a frame. A page of another origin cannot.
The dashboard has `X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'`. No page can frame it.
The headers do not depend on the template, so a custom template gets them too.

## Context version 3

Every context has `context_version` (integer, `3`). Fields are added in a minor release only if they are optional for existing templates. Removing or renaming a field is a breaking release.

### Changes from version 2

- `context_version` is `3` in all contexts. A template that tests `context_version == 2` must change.
- `login.html`: new fields `show_user_list`, `user_list_saved`, `view_cookie`, `view_cookie_path` and `admin_href`.
- `error.html` and `signed_out.html`: new field `admin_href`. The built-in pages show an "Admin" link to the dashboard in the header.
- The built-in login page opens on the Custom user form. It no longer has a `Custom…` option: the form view posts a hidden `user=__custom__`, and a switch shows the User dropdown.
- `custom_label` stays, but the built-in page no longer shows it.
- A custom `login.html` that ignores the new fields keeps working, because the POST contract is the same.
- `dashboard.html`: new field `config_file` in the page context and new field `login` in each Issuer. The built-in Login page section uses them.

No field is removed or renamed.

### Changes from version 1

- `context_version` is `2` in all four contexts. A template that tests `context_version == 1` must change.
- `login.html`: new fields `custom_label`, `custom_username`, `username` and `error_field`.
- `login.html`: new form field `username`, read when the Issuer has `custom_user`.
- `debugger.html`: a decoded JWT has the new field `issuer_note`.
- `signed_out.html`: `signed_in_as` is always null.

No field is removed or renamed.

Added later in version 2: the optional template `form_post.html` (`response_mode=form_post`). Existing `templates_dir` overrides keep working.
Also added later: the optional field `embed` of `debugger.html` (the dashboard frame). A custom `debugger.html` without it keeps working; it then shows its full page in the frame.

The autoescape writes `/` as `&#x2f;`, which a browser decodes. The `href` filter escapes like the autoescape but keeps `/`, for readable links: `<a href="{{ change_href|href }}">`.

### `login.html` and `issuer.<id>.login_template`

| Field | Type | Meaning |
| --- | --- | --- |
| `context_version` | integer | Always `3`. |
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
| `custom_label` | string | The text of the Custom user option: `issuer.<id>.custom_user.label`, else `Custom…`. The built-in page no longer shows it (version 3); a custom template can. (Version 2.) |
| `custom_username` | boolean | `true` when the Issuer has `custom_user`. Then show one `username` field instead of `custom_sub` and `custom_claims`. (Version 2.) |
| `username` | string | Prefilled text for the `username` field, for example after a form error. (Version 2.) |
| `show_user_list` | boolean | `true` when the page starts on the User dropdown, `false` on the Custom user form. Always `false` when `users` is empty. (Version 3.) |
| `user_list_saved` | boolean | `true` when this browser has a valid login view cookie (`list` or `form`). (Version 3.) |
| `view_cookie` | string | The login view cookie name, `fauxidc_login_view_{issuer_id}`. (Version 3.) |
| `view_cookie_path` | string | The `Path` of the login view cookie: the Issuer path. (Version 3.) |
| `admin_href` | string | The dashboard link of the page header, opened in a new tab. `/_mock/#issuers`, where the Users and the login page setting are. Empty for no link. (Version 3.) |

`params` must be posted back unchanged: render each pair as `<input type="hidden" name="{{ pair[0] }}" value="{{ pair[1] }}">`.

The form fields the server reads: `user` (a user `id` or `__custom__`), `custom_sub`, `custom_claims`, `override_claims`, `username`, and `remember` (checkbox). The flow needs no JavaScript.

The built-in page renders both views and posts one `user` value: the inactive view is `hidden` and its controls are `disabled`.
`show_user_list` follows this order: no Users (false); an error on `user` (true); the posted `user` after a rejected form (`__custom__` is false); a `login_hint` that names a User (true); the login view cookie; `issuer.<id>.show_user_list`.
The page script sets the cookie when the switch changes: `{{ view_cookie }}=list` or `=form`, `Path={{ view_cookie_path }}; SameSite=Lax; Max-Age=31536000`. `{issuer}/endsession` clears it.

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
| `context_version` | integer | Always `3`. |
| `issuer_id` | string | Id of the issuer. |
| `message` | string | The error message. |
| `static_base` | string | URL prefix for static files, `/_mock/static`. |
| `admin_href` | string | The dashboard link of the page header, opened in a new tab. `/_mock/#requests`, the request log. Empty for no link. (Version 3.) |

### `signed_out.html`

`/endsession` renders this page when the request has no `post_logout_redirect_uri`. It is an optional template: existing `templates_dir` overrides keep working.

| Field | Type | Meaning |
| --- | --- | --- |
| `context_version` | integer | Always `3`. |
| `issuer_id` | string | Id of the issuer. |
| `client_id` | string or null | The Client of the logout request, from `client_id` or `id_token_hint`, when known. |
| `signed_in_as` | string or null | Always null: the same response clears the Auto-select cookie. The field stays for compatibility. |
| `change_href` | string or null | The debugger `?forget=1` URL of the Issuer. It clears the Auto-select cookie. |
| `static_base` | string | URL prefix for static files, `/_mock/static`. |
| `admin_href` | string | The dashboard link of the page header, opened in a new tab. `/_mock/#issuers`. Empty for no link. (Version 3.) |

`signed_in_as` and `change_href` are optional fields. `signed_in_as` on `signed_out.html` is always null.

### `form_post.html`

`/authorize` renders this page for a request with `response_mode=form_post`, instead of the 302 of the query mode.
The response has status 200 and `Cache-Control: no-store`. It is an optional template: existing `templates_dir` overrides keep working.

| Field | Type | Meaning |
| --- | --- | --- |
| `context_version` | integer | Always `3`. |
| `issuer_id` | string | Id of the issuer. |
| `redirect_uri` | string | The validated `redirect_uri` of the request. Post the form here with `method="post"`. |
| `fields` | list of `[name, value]` | The response parameters, in order: `code` and `state` on success, or `error`, `error_description` and `state` on an error. `state` is in the list only when the request sent it. |
| `static_base` | string | URL prefix for static files, `/_mock/static`. |

Render each pair of `fields` as `<input type="hidden" name="{{ pair[0] }}" value="{{ pair[1] }}">`, and the form as
`<form method="post" action="{{ redirect_uri|href }}">`. Keep the autoescape on: `state` comes from the request.
The built-in page submits the form with a short inline script and shows a submit button for a browser without JavaScript.
The `Content-Security-Policy` header of the page has only `frame-ancestors`, so an inline script works.

### `debugger.html`

`GET {debugger}` (default path `/debugger`) renders this page. `POST {debugger}` with the form field `token` renders it with the decoded token.
The login flow callback renders it with the decoded tokens of the flow. It is a new, optional template.

| Field | Type | Meaning |
| --- | --- | --- |
| `context_version` | integer | Always `3`. |
| `issuer_id` | string | Id of the issuer. |
| `action` | string | The debugger path. Post the form here with `method="post"` and a field `token`. |
| `start_href` | string | The debugger path + `/start`. A link here starts the login flow with the built-in `debugger` Client. |
| `token` | string | The pasted value, to keep in the textarea. |
| `decoded` | decoded JWT or null | The pasted token, decoded. |
| `flow` | list of `[name, decoded JWT]` | The tokens of a finished login flow: `id_token`, `access_token`, `refresh_token` (when present). |
| `flow_raw` | string or null | The token response of a finished login flow, as pretty JSON. |
| `error` | string or null | An error message, for example `not a JWT: …` or an error of the login flow. |
| `signed_in_as` | string or null | The label (or id) of the Auto-select User, when the request cookie names a configured User. |
| `change_href` | string | The debugger path + `?forget=1`. |
| `static_base` | string | URL prefix for static files, `/_mock/static`. |
| `embed` | boolean | `true` when the page shows in the dashboard frame (`?embed=1`). Then hide the brand row and the footer. `action`, `start_href` and `change_href` then keep `embed=1`. (Added in version 2, optional.) |

`?embed=1` on `GET {debugger}`, `POST {debugger}` and `{debugger}/start` sets `embed`. Any other value than empty or `0` counts as `1`.
A login flow started with `{debugger}/start?embed=1` ends on a callback page with `embed` true. The `redirect_uri` of the flow does not change.
A callback without a flow of this browser shows the page with `embed` false.

A decoded JWT has these fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `header` | string | The header as pretty JSON. |
| `payload` | string | The payload as pretty JSON. |
| `signature_valid` | boolean | `true` when a key of this Issuer (by `kid`) verifies the signature. |
| `signature_note` | string | `valid (kid <kid>, <alg>)`, or the reason the check failed. |
| `expiry_note` | string | `exp <n>: expires in <s> s`, `exp <n>: expired <s> s ago`, or `no exp`. |
| `issuer_note` | string | `iss matches this Issuer`, `iss <value> is not this Issuer (<issuer_url>)`, or `no iss`. An exact string comparison. |

### `dashboard.html`

`GET /_mock/` renders this page. It is a new, optional template. The built-in page loads `{{ static_base|href }}/halo.css`,
`{{ static_base|href }}/dashboard.css` and `{{ static_base|href }}/dashboard.js`. The script finds its forms and buttons by `id` and `data-action`.
A custom page that loads the script must keep them, or use its own script.

| Field | Type | Meaning |
| --- | --- | --- |
| `context_version` | integer | Always `3`. |
| `issuers` | list of Issuers | Each configured Issuer, by id. |
| `request_log` | boolean | `false` when `server.request_log_size` is 0. |
| `config_file` | boolean | `true` when the server reads a config file (given, `FAUXIDC_CONFIG` or `./fauxidc.toml`). If `false`, a login setting change stays in memory. (Version 3.) |
| `config_read_only` | boolean | `true` when the last config file is read-only (no write permission, or a `:ro` mount). A login setting change then stays in memory. (Version 3, added in a minor release.) |
| `static_base` | string | URL prefix for static files, `/_mock/static`. |

An Issuer has these fields. The hrefs are paths on this server.

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string | Id of the Issuer. |
| `issuer_url` | string | The `iss` of the Issuer for this request. |
| `lenient` | boolean | `true` in Lenient mode. |
| `discovery_href` | string | The discovery document. |
| `jwks_href` | string | The JWKS endpoint. |
| `debugger_href` | string | The debugger page. The Debugger view shows it in the frame `#debugger-frame` with `?embed=1`. |
| `endsession_href` | string | The `/endsession` endpoint. A browser visit signs out: it clears the Session, the Auto-select cookie and the login view cookie. |
| `login` | object | The login page setting of the Issuer: `show_user_list` (boolean), `source` (`default`, `file`, `memory`, `env`, `inline`, `flag` or `unknown`) and `origin` (string or null: the file position, env var or flag). (Version 3.) |

The built-in `dashboard.js` needs these hooks for the Login page section:

- `data-login-issuer="{id}"` on the switch (a checkbox with `role="switch"`). The script sends `PUT /_mock/{id}/login` when it changes.
- `aria-describedby` on the switch. It names the state span (`login-state-{id}`) that the script updates with the new state text.
- `data-login-source` on the cell in the same table row (`tr`) as the switch. The script replaces its content with the source label.
- `#issuers-out`. The script shows an error of the request here.
