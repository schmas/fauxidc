# 9. One plain CSS stylesheet (halo) for every page

Date: 2026-11-16
Status: accepted.

## Context

The built-in pages (login, signed out, error, `form_post`, debugger) used `fauxidc.css`.
Tailwind CSS v4 and daisyUI v5 compiled it at dev time through `scripts/build-css.sh`.
The dashboard used a separate plain stylesheet, `dashboard.css`, with the tokens of the halo design (`docs/fauxidc-design.pen`).
So the pages had two style sources with two sets of colors. The dashboard now shows the debugger page in a frame, and the two looks did not match.

## Decision

- `assets/static/halo.css` is the only source of the halo tokens and components. It is plain CSS without a build step.
  Every built-in page links it. Light and dark follow `prefers-color-scheme`.
- `assets/static/dashboard.css` holds only the dashboard shell (sidebar, views, frame). It uses the halo tokens and does not define them again.
- The Tailwind build is removed: `assets/css/`, `scripts/build-css.sh` and the build step of the CI job `css`.
- `fauxidc.css` and `login.css` stay embedded and served, frozen, so an old custom template that links them keeps its style.
  No built-in page links them.
- The CI job `css` runs `scripts/check-css.sh`: size limits, no network URL in any stylesheet, and the SHA-256 of the frozen files.
  The job keeps its name because the ruleset `protect-main` requires it.

## Rejected options

- Keep Tailwind and daisyUI for the flow pages: two style sources, and the framed debugger does not match the dashboard.
- Build `halo.css` with Tailwind: the dashboard is already plain CSS, and a build step adds downloads and a CI rebuild for a small file.
- Remove `fauxidc.css`: an old custom template that links it would lose its style without warning.

## Consequences

- A style change is an edit to `halo.css` or `dashboard.css`. No tool download and no generated file to commit.
- A template can use only the classes that `halo.css` and `dashboard.css` define. `docs/templates.md` lists the main ones.
- The frozen files never get new classes. A custom template that wants the new look links `halo.css`.
