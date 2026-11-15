# M4 pages: manual visual check

This runbook checks the design of the four built-in pages: `login.html`, `error.html`, `signed_out.html` and `debugger.html`.
The automated tests check the markup and the CSS (`tests/templates.rs`, `tests/debugger.rs`, `e2e/spa/tests/login-page.spec.ts`, `e2e/spa/tests/login-username.spec.ts`).
This runbook checks what a person sees. Record the results in the table at the end.

## Prerequisites

- A fauxidc checkout. Port 9000 must be free.
- A desktop browser with developer tools (Chrome or Firefox). You can set the color scheme, the window size and JavaScript in the developer tools.

## Start the server

```sh
cargo run -- --config examples/auth0.toml --config e2e/spa/custom-user.toml
```

`e2e/spa/custom-user.toml` adds the Issuer `custom` with a Custom user template (`custom_user`, label "Other…").
Its login page shows the username mode.

## Pages

| Page | How to open it |
| --- | --- |
| Login | `http://localhost:9000/auth0/authorize?client_id=example-spa&redirect_uri=http://localhost:5173/&response_type=code&scope=openid&state=x&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256` |
| Login with an error | On the login page, select "Custom…", leave Subject empty and click "Sign in". |
| Login, username mode | The Login URL with `/custom/authorize` in place of `/auth0/authorize`. |
| Login, username mode with an error | On the username mode page, select "Other…", leave Username empty and click "Sign in". |
| Error | `http://localhost:9000/auth0/authorize?client_id=nope&redirect_uri=http://x/cb&response_type=code` |
| Signed out | `http://localhost:9000/auth0/v2/logout` |
| Debugger, pasted token | Get a token with `curl -s -X POST localhost:9000/_mock/auth0/token -H 'content-type: application/json' -d '{"user":"alice"}'`. Open `http://localhost:9000/auth0/debugger`, paste the `access_token` value and click "Decode". |
| Debugger, login flow | On the debugger page, click "Run login flow", then "Sign in". |

## Sizes and modes

- Desktop: 1280x720 and 1440x900.
- Phone: 375 px wide (for example 375x740).
- Light and dark: set the color scheme in the developer tools (Chrome: Rendering, "Emulate CSS media feature prefers-color-scheme") or in the OS.
- JavaScript off: only for the login page (Chrome: Settings, Debugger, "Disable JavaScript").

## Checks

1. Login, no page scroll: at 1280x720 and at 1440x900, in light and dark, the page has no vertical scroll bar in these states:
   a config User selected, "Custom…" selected, and "Custom…" selected with "Override claims" open.
   The "Sign in" button is visible in each state.
2. Login with an error: the red alert shows the message. Only the field that failed gets a red border and `aria-invalid="true"` (context field `error_field`).
   Example: an empty Subject marks only Subject. Invalid Override claims JSON marks only the Override claims field and keeps the section open.
   On a desktop, if the card content is taller than the window, the card body scrolls and the "Sign in" button stays visible.
3. Login, Custom user: the Custom User fields show only when "Custom…" is selected.
4. Login with JavaScript off: the Custom User fields are always visible, with the note "only for Custom…" inside the legend line.
   Select "Custom…", type `carol` as Subject and click "Sign in". The browser goes to `http://localhost:5173/?code=…`.
5. Focus: press Tab through the login form. Each control shows a visible focus ring.
6. Error and signed-out pages: no page scroll at 1280x720 and 1440x900, light and dark.
7. Debugger: the page can scroll. The form card at the top is compact. Each token card shows the badges (signature, iss, expired) and the Header and Payload code blocks.
8. Debugger at 375 px: a long JWT or token response wraps inside its code block. The page has no horizontal scroll.
9. Every page at 375 px: no horizontal scroll, and the wordmark and the "Mock server · not for production" badge are visible.
   Below the `sm` breakpoint (640 px) the login page may scroll as a whole page; every field and the "Sign in" button can be reached.
   Open the error page with a long `redirect_uri` (for example 600 characters with no break point): the message wraps inside the alert, at 375 px and at 1280 px.
10. Network: in the developer tools Network tab, each page loads only `localhost:9000` URLs.
11. Contrast: in light and dark, every text and badge has a contrast ratio of at least 4.5:1 against its background (WCAG AA for small text).
    Check with the DevTools color picker (it shows the ratio) or the Lighthouse accessibility audit. Check the help texts, the footer, the "Mock server" badge, the Client and Issuer chips, the alerts and the debugger badges.
12. Username mode: on the username mode page, "Other…" shows one Username field and no Subject or Claims field.
    Check the no-page-scroll rule of check 1 at 1280x720 and 1440x900, light and dark, in these states:
    "Other…" selected, "Other…" selected with "Override claims" open, and the empty-username error with and without "Override claims" open.
    The "Sign in" button is visible in each state. At 375 px and 1280 px there is no horizontal scroll.
13. Username mode with an error: the alert says "Enter a username". Only the Username field has a red border.
14. Username mode with JavaScript off: the Username field is always visible, with the note "only for Other…" in the legend line.
    Select "Other…", type `  Carol ` and click "Sign in". The browser goes to `http://localhost:5173/?code=…`. The id_token `sub` is `carol`.
15. Username mode contrast: check 11 for the username mode states, light and dark.

## Screenshots

Save the screenshots to `.agents/plans/2026-11-15-fauxidc-m4/screenshots/` (git-ignored, for the reviewer and the owner).
Name them `<page>-<light|dark>-<desktop|mobile>.png`, for example `login-dark-desktop.png`.
Desktop is 1280x720. Mobile is 375 px wide.

## Results

| # | Check | Result |
| --- | --- | --- |
| 1 | Login, no page scroll (1280x720, 1440x900, light, dark, three states) | pass, 2026-11-15 |
| 2 | Login with an error | pass, 2026-11-15 |
| 3 | Login, Custom user fields show only for "Custom…" | pass, 2026-11-15 |
| 4 | Login with JavaScript off | pass, 2026-11-15 |
| 5 | Focus rings | pass, 2026-11-15 |
| 6 | Error and signed-out pages, no page scroll | pass, 2026-11-15 |
| 7 | Debugger layout and badges | pass, 2026-11-15 |
| 8 | Debugger at 375 px, code blocks wrap | pass, 2026-11-15 |
| 9 | Every page at 375 px, long error message wraps | pass, 2026-11-15 |
| 10 | Only `localhost:9000` URLs | pass, 2026-11-15 |
| 11 | Contrast at least 4.5:1, light and dark (lowest: 4.97 light "signature valid", 5.27 dark alert text) | pass, 2026-11-15 |
| 2 | Login with an error marks only the failed field (part 4 re-run in the browser: empty Subject; the other fields in `tests/templates.rs`) | pass, 2026-11-15 |
| 12 | Username mode, no page scroll (1280x720, 1440x900, light, dark, four states); no horizontal scroll at 375 px and 1280 px | pass, 2026-11-15 |
| 13 | Username mode with an error marks only Username | pass, 2026-11-15 |
| 14 | Username mode with JavaScript off | pass, 2026-11-15 |
| 15 | Username mode contrast at least 4.5:1 (lowest: 5.14 light "Mock server" badge, 5.27 dark alert text) | pass, 2026-11-15 |

The 2026-11-15 run used Chromium through a Playwright script outside the repo (light and dark, 1280x720, 1440x900 and 375x740, JavaScript on and off).
The script measured the page scroll, the horizontal overflow and the "Sign in" button position for each page and state.
Screenshots use `reducedMotion: "reduce"`, so the "Override claims" open state is captured after it opens.
For check 11, the script composited each text color over its effective background and computed the WCAG ratio for every text element.
The automated Playwright spec `e2e/spa/tests/login-page.spec.ts` also checks the long error message at 375 px and 1280 px.

The part 4 run (checks 2 and 12 to 15) used the same kind of script on the `custom` Issuer: light and dark, 1280x720, 1440x900 and 375x740, JavaScript on and off.
Its screenshots are `login-username-*`, `login-username-override-*`, `login-username-error-*` and `login-username-nojs-*`. `login-error-*` was taken again, because the Subject field is now marked.
The automated spec `e2e/spa/tests/login-username.spec.ts` checks the username toggle, the no-JavaScript flow, the marked field,
no horizontal scroll at 375 px and 1280 px, and no page scroll at 1280x720 and 1440x900.
