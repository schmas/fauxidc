// The fauxidc dashboard (/_mock/). It calls the JSON routes of the Test API, the same
// routes that curl and tests use (docs/test-api.md). No framework and no build step.
// Every value from the server goes into the page through textContent, never as HTML.
// The layout follows docs/fauxidc-design.pen.
"use strict";
(() => {
  const $ = (selector, root = document) => root.querySelector(selector);
  const SVG = "http" + "://www.w3.org/2000/svg";

  /** A new element with a class and children (strings become text). */
  function el(tag, className, ...children) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    for (const child of children) if (child !== null && child !== undefined) node.append(child);
    return node;
  }

  /** An icon from the sprite in the page (`#i-<name>`). */
  function icon(name) {
    const svg = document.createElementNS(SVG, "svg");
    svg.setAttribute("class", "ic");
    svg.setAttribute("aria-hidden", "true");
    const use = document.createElementNS(SVG, "use");
    use.setAttribute("href", `#i-${name}`);
    svg.append(use);
    return svg;
  }

  function button(label, iconName, kind, action) {
    const b = el("button", `btn${kind ? ` btn-${kind}` : ""}`, iconName ? icon(iconName) : null, label);
    b.type = "button";
    b.addEventListener("click", action);
    return b;
  }

  function label(text, kind) {
    return el("span", `label${kind ? ` label-${kind}` : ""}`, text);
  }

  function pretty(value) {
    return JSON.stringify(value, null, 2);
  }

  class ApiError extends Error {
    constructor(status, data) {
      const d = data && typeof data === "object" ? data : {};
      const code = [status, d.error].filter(Boolean).join(" ");
      super(`${code}: ${d.error_description || (typeof data === "string" && data) || "request failed"}`);
      this.errors = Array.isArray(d.errors) ? d.errors : [];
    }
  }

  /** Calls the Test API. Returns the parsed body; throws ApiError for a status >= 400. */
  async function api(method, path, body) {
    const init = { method, headers: { accept: "application/json" } };
    if (body !== undefined) {
      init.headers["content-type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    const res = await fetch(path, init);
    const text = await res.text();
    let data = text;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      // A TOML or empty body stays text.
    }
    if (!res.ok) throw new ApiError(res.status, data);
    return data;
  }

  function codeBlock(value) {
    return el("pre", "code", typeof value === "string" ? value : pretty(value));
  }

  const ALERT_ICONS = { error: "alert", success: "check", warning: "warn" };

  /** Shows an alert (and an optional JSON value) in the output area `id`. */
  function show(id, kind, title, detail, value) {
    const out = document.getElementById(id);
    if (!out) return;
    const body = el("div", "", el("strong", "", title));
    if (detail) body.append(el("span", "", detail));
    if (value instanceof ApiError && value.errors.length) body.append(el("span", "lines", value.errors.join("\n")));
    const alert = el("div", `alert alert-${kind}`, icon(ALERT_ICONS[kind]), body);
    alert.setAttribute("role", kind === "error" ? "alert" : "status");
    out.replaceChildren(alert);
    if (value !== undefined && !(value instanceof ApiError)) out.append(codeBlock(value));
  }

  /** Runs `work`; shows its error message in the output area `id`. */
  async function run(id, work) {
    try {
      await work();
    } catch (e) {
      show(id, "error", e.message, null, e instanceof ApiError ? e : undefined);
    }
  }

  function emptyRow(tbody, columns, text) {
    const td = el("td", "empty", text);
    td.colSpan = columns;
    tbody.replaceChildren(el("tr", "", td));
  }

  // Views -------------------------------------------------------------------------------

  const VIEWS = [...document.querySelectorAll(".view")].map((v) => v.id);
  const loaded = new Set();

  /** The view and its argument in the URL fragment: `#debugger/auth0` is view `debugger`, argument `auth0`. */
  function route() {
    const hash = location.hash.slice(1);
    const at = hash.indexOf("/");
    const name = at < 0 ? hash : hash.slice(0, at);
    let arg = "";
    if (at >= 0) {
      try {
        arg = decodeURIComponent(hash.slice(at + 1));
      } catch {
        // A broken escape: no argument.
      }
    }
    return VIEWS.includes(name) ? { name, arg } : { name: VIEWS[0], arg: "" };
  }

  function showView() {
    const { name, arg } = route();
    if (name === "debugger") showDebugger(arg);
    for (const id of VIEWS) document.getElementById(id).hidden = id !== name;
    for (const a of document.querySelectorAll(".nav-item")) {
      if (a.dataset.view === name) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    }
    $("#nav-select").value = name;
    if (!loaded.has(name)) {
      loaded.add(name);
      const load = LOADERS[name];
      if (load) load();
    }
  }

  // Debugger ---------------------------------------------------------------------------
  // The debugger page of the chosen Issuer runs in a same-origin frame with ?embed=1.
  // The page is the same one that {issuer}/debugger serves; the frame only hides its brand row.

  const debuggerSelect = $("#debugger-issuer");
  const debuggerFrame = $("#debugger-frame");
  const debuggerOpen = $("#debugger-open");
  let debuggerIssuer = null;

  /** The debugger path of Issuer `id`, or null for an unknown Issuer. */
  function debuggerHref(id) {
    const option = [...debuggerSelect.options].find((o) => o.value === id);
    return option ? option.dataset.debuggerHref : null;
  }

  /** Shows the debugger of Issuer `id` (else the selected one) and keeps it in the URL fragment.
   * `load` false: the caller fills the frame itself (a form with target="debugger-frame"). */
  function showDebugger(id, load = true) {
    if (!debuggerSelect || !debuggerSelect.options.length) return;
    if (!debuggerHref(id)) id = debuggerIssuer || debuggerSelect.value;
    debuggerSelect.value = id;
    const href = debuggerHref(id);
    debuggerOpen.href = href;
    const hash = `#debugger/${encodeURIComponent(id)}`;
    if (location.hash !== hash) history.replaceState(null, "", hash);
    if (debuggerIssuer === id) return;
    debuggerIssuer = id;
    if (load) debuggerFrame.src = `${href}?embed=1`;
  }

  /** The frame takes the height of its page, and at least the rest of the screen (CSS). */
  function fitDebuggerFrame() {
    try {
      const doc = debuggerFrame.contentDocument;
      if (!doc || !doc.body) return;
      // The body height, not the document height: the document is never smaller than the frame.
      const resize = () => {
        debuggerFrame.style.height = `${Math.ceil(doc.body.getBoundingClientRect().height)}px`;
      };
      debuggerFrame.style.height = "";
      new ResizeObserver(resize).observe(doc.body);
      resize();
    } catch {
      // Another origin (a misconfigured issuer_url host): keep the CSS height.
    }
  }

  if (debuggerFrame) debuggerFrame.addEventListener("load", fitDebuggerFrame);
  if (debuggerSelect) {
    debuggerSelect.addEventListener("change", () => {
      location.hash = `debugger/${encodeURIComponent(debuggerSelect.value)}`;
    });
  }

  // Users and Clients -----------------------------------------------------------------

  const KINDS = {
    users: {
      noun: "User",
      idField: "id",
      blank: { id: "new_user", label: "New User", claims: { email: "new_user@example.test" } },
      readOnly: [],
      columns: 5,
      cells: (u) => {
        const claims = u.claims || {};
        const roles = Array.isArray(claims.roles) ? `roles: ${claims.roles.join(", ")}` : `${Object.keys(claims).length} claims`;
        return [el("td", "mono", u.id), el("td", "", u.label || ""), el("td", "muted", claims.email || ""), el("td", "", label(roles))];
      },
    },
    clients: {
      noun: "Client",
      idField: "key",
      blank: {
        key: "new_client",
        client_secret: "change-me",
        redirect_uris: ["http://localhost:3000/callback"],
        grant_types: ["authorization_code", "refresh_token"],
      },
      readOnly: ["lenient"],
      columns: 6,
      cells: (c) => [
        el("td", "mono", c.key),
        el("td", "mono", c.client_id),
        el("td", "muted", (c.grant_types || []).join(", ")),
        el("td", c.client_secret ? "mono" : "muted", c.client_secret ? c.client_secret : "none"),
        el("td", "", c.lenient ? label("Lenient · in memory", "warning") : label("Config", "success")),
      ],
    },
  };

  const cache = { users: [], clients: [] };
  /** The open editor: `{ kind, original }`; `original` is null for a new entry. */
  let editing = null;

  function asList(data) {
    return Array.isArray(data) ? data : Object.values(data || {});
  }

  async function list(kind) {
    const k = KINDS[kind];
    const items = asList(await api("GET", `/_mock/${kind}`));
    cache[kind] = items;
    const tbody = document.getElementById(`${kind}-list`);
    if (items.length === 0) emptyRow(tbody, k.columns, `No ${k.noun}s.`);
    else tbody.replaceChildren(...items.map((item) => row(kind, item)));
    if (kind === "users") fillUserSelect(items);
  }

  function row(kind, item) {
    const k = KINDS[kind];
    const id = item[k.idField];
    const actions = el("div", "row");
    if (item.lenient) {
      actions.append(button("View", "eye", "outline", () => openEditor(kind, item, true)));
    } else {
      actions.append(button("Edit", "pencil", "outline", () => openEditor(kind, item, false)));
      actions.append(button("Delete", "trash", "ghost", () => remove(kind, id)));
    }
    const tr = el("tr", "", ...k.cells(item), el("td", "actions", actions));
    tr.dataset.id = id;
    return tr;
  }

  function openEditor(kind, item, readOnly) {
    const k = KINDS[kind];
    const dialog = $("#editor");
    editing = { kind, original: item };
    const id = item ? item[k.idField] : "";
    $("#editor-title").textContent = item ? `${readOnly ? "View" : "Edit"} ${k.noun} ${id}` : `New ${k.noun}`;
    $("[data-help]", dialog).textContent = readOnly
      ? "A Lenient-registered Client lives in memory only. To keep it, add a Client with the same client_id."
      : item
        ? `Save sends only the changed fields (JSON Merge Patch). Remove a field to reset it. "***" is a masked secret: leave it to keep the secret.`
        : `The new ${k.noun} goes into the last config file. "${k.idField}" must match [a-z0-9_]+.`;
    $("[data-label]", dialog).textContent = `${k.noun} (JSON${readOnly ? ", read-only" : ""})`;
    const textarea = $("#editor-json");
    textarea.value = pretty(item || k.blank);
    textarea.readOnly = readOnly;
    $("[data-save]", dialog).hidden = readOnly;
    $("[data-action=cancel]", dialog).lastChild.textContent = readOnly ? "Close" : "Cancel";
    $("#editor-out").replaceChildren();
    dialog.showModal();
    textarea.focus();
    textarea.setSelectionRange(0, 0);
  }

  function closeEditor() {
    $("#editor").close();
    editing = null;
  }

  function isObject(v) {
    return v !== null && typeof v === "object" && !Array.isArray(v);
  }

  /** The JSON Merge Patch (RFC 7396) that turns `a` into `b`. */
  function mergePatch(a, b) {
    const patch = {};
    for (const key of Object.keys(a)) if (!(key in b)) patch[key] = null;
    for (const [key, value] of Object.entries(b)) {
      const old = a[key];
      if (JSON.stringify(old) === JSON.stringify(value)) continue;
      patch[key] = isObject(old) && isObject(value) ? mergePatch(old, value) : value;
    }
    return patch;
  }

  async function save() {
    const { kind, original } = editing;
    const k = KINDS[kind];
    let value;
    try {
      value = JSON.parse($("#editor-json").value);
    } catch (e) {
      throw new Error(`invalid JSON: ${e.message}`);
    }
    if (!isObject(value)) throw new Error(`a ${k.noun} is a JSON object`);
    if (!original) {
      const created = await api("POST", `/_mock/${kind}`, value);
      show(`${kind}-out`, "success", `Added ${k.noun} ${created[k.idField]}.`);
    } else {
      const id = original[k.idField];
      if (value[k.idField] !== id) {
        throw new Error(`"${k.idField}" cannot change. Add a new ${k.noun} and delete the old one.`);
      }
      const strip = (o) => {
        const copy = { ...o };
        for (const field of [k.idField, ...k.readOnly]) delete copy[field];
        return copy;
      };
      const patch = mergePatch(strip(original), strip(value));
      if (Object.keys(patch).length === 0) {
        show(`${kind}-out`, "success", "No changes.");
        closeEditor();
        return;
      }
      await api("PATCH", `/_mock/${kind}/${encodeURIComponent(id)}`, patch);
      show(`${kind}-out`, "success", `Saved ${k.noun} ${id}.`);
    }
    closeEditor();
    await list(kind);
  }

  async function remove(kind, id) {
    const k = KINDS[kind];
    if (!window.confirm(`Delete ${k.noun} ${id} from the config file?`)) return;
    await run(`${kind}-out`, async () => {
      await api("DELETE", `/_mock/${kind}/${encodeURIComponent(id)}`);
      show(`${kind}-out`, "success", `Deleted ${k.noun} ${id}.`);
      await list(kind);
    });
  }

  // Keys ----------------------------------------------------------------------------------

  /** Fills the Keys table from the public JWKS of each Issuer. */
  async function loadKeys() {
    for (const tr of document.querySelectorAll("[data-key-row]")) {
      try {
        const res = await fetch(tr.dataset.jwksHref);
        const keys = (await res.json()).keys || [];
        const active = keys[0] || {};
        $("[data-alg]", tr).replaceChildren(label(active.alg || "?"));
        $("[data-kid]", tr).textContent = active.kid || "";
        $("[data-count]", tr).textContent = String(keys.length);
      } catch {
        $("[data-kid]", tr).textContent = "JWKS not available";
      }
    }
  }

  async function rotate(issuer, retire) {
    const result = await api("POST", `/_mock/${encodeURIComponent(issuer)}/rotate-key${retire ? "?retire=true" : ""}`);
    const retired = result.retired.length
      ? `Retired ${result.retired.length} key(s): ${result.retired.join(", ")}. Tokens signed with them fail now.`
      : "Older keys stay in JWKS, so their tokens still verify.";
    show("keys-out", "success", `Issuer ${issuer} has the new key ${result.kid}.`, retired);
    await loadKeys();
  }

  // Token -----------------------------------------------------------------------------------

  function fillUserSelect(users) {
    const select = $("#token-form [data-users]");
    const current = select.value;
    const custom = $("option[value=__custom__]", select);
    select.replaceChildren(
      ...users.map((u) => {
        const option = el("option", "", u.label ? `${u.label} (${u.id})` : u.id);
        option.value = u.id;
        return option;
      }),
      custom,
    );
    // The first fill selects the first User; a later fill keeps the choice.
    if (select.dataset.filled && [...select.options].some((o) => o.value === current)) {
      select.value = current;
    } else {
      select.selectedIndex = 0;
    }
    select.dataset.filled = "1";
  }

  /** The non-empty text fields of `form` named in `names`. */
  function fields(form, names) {
    const out = {};
    for (const name of names) {
      const value = form.elements[name].value.trim();
      if (value !== "") out[name] = value;
    }
    return out;
  }

  function numbers(body, names) {
    for (const name of names) if (name in body) body[name] = Number(body[name]);
    return body;
  }

  async function mintToken(form) {
    const issuer = form.elements.issuer.value;
    const body = numbers(fields(form, ["sub", "client_id", "scope", "audience", "expires_in", "claims"]), ["expires_in"]);
    if (form.elements.user.value !== "__custom__") {
      body.user = form.elements.user.value;
      delete body.sub;
    }
    if (body.claims) {
      try {
        body.claims = JSON.parse(body.claims);
      } catch (e) {
        throw new Error(`Claims: invalid JSON: ${e.message}`);
      }
    }
    const tokens = await api("POST", `/_mock/${encodeURIComponent(issuer)}/token`, body);
    show(
      "token-out",
      "success",
      `Token for ${body.user || body.sub || "?"} from Issuer ${issuer}`,
      `Expires in ${tokens.expires_in} s. Decode it in the debugger to check the signature.`,
      tokens,
    );
    const href = debuggerHref(issuer);
    const token = tokens.id_token || tokens.access_token;
    if (href && token) {
      // The debugger page decodes a posted token and checks it with the keys of the Issuer.
      // The form posts into the frame of the Debugger view.
      const decode = el("form", "row");
      decode.method = "post";
      decode.action = `${href}?embed=1`;
      decode.target = "debugger-frame";
      decode.addEventListener("submit", () => {
        history.pushState(null, "", `#debugger/${encodeURIComponent(issuer)}`);
        debuggerIssuer = null;
        showDebugger(issuer, false);
        showView();
      });
      const input = el("input");
      input.type = "hidden";
      input.name = "token";
      input.value = token;
      const submit = el("button", "btn btn-outline", icon("link"), `Decode the ${tokens.id_token ? "id_token" : "access_token"} in the debugger`);
      submit.type = "submit";
      decode.append(input, submit);
      $("#token-out").append(decode);
    }
  }

  // Failures, Request log, config, reset ----------------------------------------------------

  async function setFailure(form) {
    const issuer = form.elements.issuer.value;
    const body = numbers(fields(form, ["endpoint", "status", "error", "count", "delay_ms"]), ["status", "count", "delay_ms"]);
    await api("POST", `/_mock/${encodeURIComponent(issuer)}/fail-next`, body);
    const count = body.count ?? 1;
    show(
      "fail-out",
      "success",
      `The next ${count} ${body.endpoint} request(s) of Issuer ${issuer} use this failure.`,
      "Clear removes every failure of the Issuer. The Test API has no list of active failures.",
      body,
    );
  }

  async function clearFailures(form) {
    const issuer = form.elements.issuer.value;
    await api("DELETE", `/_mock/${encodeURIComponent(issuer)}/fail-next`);
    show("fail-out", "success", `Cleared the Injected failures of Issuer ${issuer}.`);
  }

  async function showLog(form) {
    const query = new URLSearchParams(fields(form, ["issuer", "path"]));
    const entries = await api("GET", `/_mock/requests${query.size ? `?${query}` : ""}`);
    const tbody = $("#log-list");
    $("#log-out").replaceChildren();
    if (entries.length === 0) {
      emptyRow(tbody, 6, "No requests.");
      return;
    }
    const rows = [];
    // Newest first.
    for (const e of [...entries].reverse()) {
      const time = new Date(e.time * 1000).toLocaleTimeString();
      const toggle = el("button", "toggle", icon("chevron"));
      toggle.type = "button";
      toggle.setAttribute("aria-expanded", "false");
      toggle.setAttribute("aria-label", `Details of request ${e.id}`);
      const detailCell = el("td", "", codeBlock({ headers: e.headers, body: e.body }));
      detailCell.colSpan = 6;
      const detail = el("tr", "detail", detailCell);
      detail.hidden = true;
      toggle.addEventListener("click", () => {
        detail.hidden = !detail.hidden;
        toggle.setAttribute("aria-expanded", String(!detail.hidden));
      });
      const status = label(String(e.status), e.status >= 400 ? "warning" : "success");
      rows.push(
        el(
          "tr",
          "",
          el("td", "", toggle),
          el("td", "", status),
          el("td", "mono", e.method),
          el("td", "mono", e.path + (e.query ? `?${e.query}` : "")),
          el("td", "mono", e.issuer || ""),
          el("td", "muted", `${time} · #${e.id}`),
        ),
        detail,
      );
    }
    tbody.replaceChildren(...rows);
  }

  async function clearLog() {
    if (!window.confirm("Clear every entry of the Request log?")) return;
    await api("DELETE", "/_mock/requests");
    emptyRow($("#log-list"), 6, "No requests.");
    show("log-out", "success", "Cleared the Request log.");
  }

  async function showConfig(format) {
    for (const tab of document.querySelectorAll("#config .tab")) {
      tab.setAttribute("aria-selected", String(tab.dataset.action === `config-${format}`));
    }
    const data = await api("GET", format === "toml" ? "/_mock/config?format=toml" : "/_mock/config");
    $("#config-view").textContent = typeof data === "string" ? data : pretty(data);
  }

  /** Reloads the config files; shows the answer in the output area `id`. */
  async function reload(id) {
    const result = await api("POST", "/_mock/reload");
    const title = result.changed ? "Reloaded the config files. The new config applies now." : "The config files did not change.";
    show(id, "success", title, result.warnings.length ? result.warnings.join("\n") : null);
    if (result.changed) {
      await Promise.all([run("users-out", () => list("users")), run("clients-out", () => list("clients"))]);
    }
  }

  async function resetState(issuer, outId) {
    const what = issuer ? `the runtime state of Issuer ${issuer}` : "the runtime state of all Issuers";
    if (!window.confirm(`Reset ${what}? Codes, Sessions, Injected failures and the Request log go away.`)) return;
    await api("DELETE", issuer ? `/_mock/state?issuer=${encodeURIComponent(issuer)}` : "/_mock/state");
    show(outId, "success", `Reset ${what}.`);
    // A reset removes the Lenient-registered Clients.
    await run("clients-out", () => list("clients"));
  }

  // Wiring ----------------------------------------------------------------------------------

  const LOADERS = {
    keys: () => loadKeys(),
    config: () => run("config-out", () => showConfig("json")),
    requests: () => run("log-out", () => showLog($("#log-form"))),
  };

  /** The output area of the view that holds `node`. */
  const outOf = (node) => `${node.closest(".view").id}-out`;

  const ACTIONS = {
    "reset-issuer": (b) => run("issuers-out", () => resetState(b.dataset.issuer, "issuers-out")),
    rotate: (b) => run("keys-out", () => rotate(b.dataset.issuer, false)),
    retire: (b) => run("keys-out", () => rotate(b.dataset.issuer, true)),
    list: (b) => run(`${b.dataset.kind}-out`, () => list(b.dataset.kind)),
    new: (b) => openEditor(b.dataset.kind, null, false),
    cancel: () => closeEditor(),
    "fail-clear": () => run("fail-out", () => clearFailures($("#fail-form"))),
    "log-clear": () => run("log-out", clearLog),
    "config-json": () => run("config-out", () => showConfig("json")),
    "config-toml": () => run("config-out", () => showConfig("toml")),
    reload: (b) => run(outOf(b), () => reload(outOf(b))),
  };

  document.addEventListener("click", (event) => {
    const b = event.target.closest("button[data-action]");
    if (b && ACTIONS[b.dataset.action]) ACTIONS[b.dataset.action](b);
  });

  const SUBMITS = {
    "editor-form": () => run("editor-out", save),
    "token-form": (form) => run("token-out", () => mintToken(form)),
    "fail-form": (form) => run("fail-out", () => setFailure(form)),
    "log-form": (form) => run("log-out", () => showLog(form)),
    "reset-form": (form) => run("reset-out", () => resetState(form.elements.issuer.value, "reset-out")),
  };

  document.addEventListener("submit", (event) => {
    const handler = SUBMITS[event.target.id];
    if (!handler) return;
    event.preventDefault();
    handler(event.target);
  });

  $("#editor").addEventListener("close", () => {
    editing = null;
  });
  $("#nav-select").addEventListener("change", (event) => {
    location.hash = event.target.value;
  });
  window.addEventListener("hashchange", showView);

  showView();
  run("users-out", () => list("users"));
  run("clients-out", () => list("clients"));
})();
