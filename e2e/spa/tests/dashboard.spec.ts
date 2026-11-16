import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { expect, test, type Page } from "@playwright/test";

// The admin dashboard (/_mock/): one check per section, through the page.
// The server of playwright.config.ts writes Users and Clients to its last config file,
// custom-user.toml. The test keeps its text and writes it back at the end.

const MOCK = "http://localhost:9000";
const CONFIG = fileURLToPath(new URL("../custom-user.toml", import.meta.url));
let configText = "";

test.describe.configure({ mode: "serial" });

test.beforeAll(() => {
  configText = readFileSync(CONFIG, "utf8");
});

test.afterAll(async ({ request }) => {
  writeFileSync(CONFIG, configText);
  await request.post(`${MOCK}/_mock/reload`);
});

const confirming = new WeakSet<Page>();

async function open(page: Page, view = "") {
  if (!confirming.has(page)) {
    confirming.add(page);
    page.on("dialog", (dialog) => dialog.accept());
  }
  await page.goto(`${MOCK}/`);
  await expect(page).toHaveURL(`${MOCK}/_mock/`);
  await expect(page.locator("#users-list")).toContainText("alice");
  if (view) await page.locator(`.nav-item[data-view="${view}"]`).click();
}

async function editJson(page: Page, change: (value: Record<string, unknown>) => void) {
  const value = JSON.parse(await page.locator("#editor-json").inputValue());
  change(value);
  await page.locator("#editor-json").fill(JSON.stringify(value));
  await page.locator("#editor [data-save]").click();
}

test("lists the Issuers with their links", async ({ page }) => {
  await open(page);
  for (const id of ["auth0", "okta", "custom"]) {
    await expect(page.locator(`[data-issuer-row="${id}"]`)).toBeVisible();
  }
  const auth0 = page.locator('[data-issuer-row="auth0"]');
  await expect(auth0.getByRole("link", { name: "Discovery" })).toHaveAttribute(
    "href",
    "/auth0/.well-known/openid-configuration",
  );
  await expect(auth0.getByRole("link", { name: "Sign out" })).toHaveAttribute("href", /\/auth0\/.+/);
});

test("rotates a key and resets the state", async ({ page }) => {
  await open(page, "keys");
  await expect(page.locator('[data-key-row="auth0"] [data-count]')).not.toBeEmpty();
  await page.locator('[data-action=rotate][data-issuer="auth0"]').click();
  await expect(page.locator("#keys-out")).toContainText("Issuer auth0 has the new key");
  await open(page, "issuers");
  await page.locator('[data-action=reset-issuer][data-issuer="okta"]').click();
  await expect(page.locator("#issuers-out")).toContainText("Reset the runtime state of Issuer okta.");
});

test("adds, changes and deletes a User", async ({ page }) => {
  await open(page, "users");
  await page.locator('[data-action=new][data-kind=users]').click();
  await page.locator("#editor-json").fill(JSON.stringify({ id: "dash_user", label: "Dash", claims: { email: "dash@example.test" } }));
  await page.locator("#editor [data-save]").click();
  await expect(page.locator("#users-out")).toContainText("Added User dash_user.");
  await expect(page.locator("#editor")).not.toBeVisible();
  const row = page.locator("#users-list tr", { hasText: "dash_user" });
  await row.getByRole("button", { name: "Edit" }).click();
  await editJson(page, (user) => {
    user.label = "Dash Example";
  });
  await expect(page.locator("#users-out")).toContainText("Saved User dash_user.");
  await expect(row).toContainText("Dash Example");
  await row.getByRole("button", { name: "Delete" }).click();
  await expect(page.locator("#users-out")).toContainText("Deleted User dash_user.");
  await expect(page.locator("#users-list")).not.toContainText("dash_user");
});

test("shows the 409 of a User from another file", async ({ page }) => {
  await open(page, "users");
  await page.locator("#users-list tr", { hasText: "alice" }).getByRole("button", { name: "Edit" }).click();
  await editJson(page, (user) => {
    user.label = "Changed";
  });
  await expect(page.locator("#editor-out [role=alert]")).toContainText("409 conflict");
  await expect(page.locator("#editor")).toBeVisible();
});

test("shows Clients with masked secrets and saves no change", async ({ page }) => {
  await open(page, "clients");
  const row = page.locator("#clients-list tr", { hasText: "example_app" });
  await expect(row).toContainText("***");
  await row.getByRole("button", { name: "Edit" }).click();
  await expect(page.locator("#editor-json")).toHaveValue(/"client_secret": "\*\*\*"/);
  await page.locator("#editor [data-save]").click();
  await expect(page.locator("#clients-out")).toContainText("No changes.");
});

test("mints a token and sets and clears an Injected failure", async ({ page }) => {
  await open(page, "token");
  await page.locator("#token-form select[name=issuer]").selectOption("auth0");
  await page.locator("#token-form select[name=user]").selectOption("alice");
  await page.locator("#token-form button[type=submit]").click();
  await expect(page.locator("#token-out")).toContainText("access_token");
  await page.getByRole("button", { name: "Decode the id_token in the debugger" }).click();
  // The token posts into the frame of the Debugger view.
  await expect(page).toHaveURL(`${MOCK}/_mock/#debugger/auth0`);
  const frame = page.frameLocator("#debugger-frame");
  await expect(frame.locator(".label-success").first()).toHaveText("signature valid");
  await expect(frame.locator("h2", { hasText: "Decoded" })).toBeVisible();
  await open(page, "failures");

  await page.locator("#fail-form select[name=issuer]").selectOption("auth0");
  await page.locator("#fail-form select[name=endpoint]").selectOption("userinfo");
  await page.locator("#fail-form input[name=status]").fill("503");
  await page.locator("#fail-form button[type=submit]").click();
  await expect(page.locator("#fail-out")).toContainText("userinfo request(s) of Issuer auth0");
  await page.locator("[data-action=fail-clear]").click();
  await expect(page.locator("#fail-out")).toContainText("Cleared the Injected failures of Issuer auth0.");
});

test("shows and clears the Request log, shows and reloads the config", async ({ page, request }) => {
  await request.get(`${MOCK}/auth0/.well-known/openid-configuration`);
  await open(page, "requests");
  await page.locator("#log-form input[name=path]").fill("/auth0/.well-known/openid-configuration");
  await page.locator("#log-form button[type=submit]").click();
  await expect(page.locator("#log-list tr").first()).toContainText("/auth0/.well-known/openid-configuration");
  await page.locator("#log-list .toggle").first().click();
  await expect(page.locator("#log-list tr.detail").first()).toBeVisible();
  await page.locator("[data-action=log-clear]").click();
  await expect(page.locator("#log-out")).toContainText("Cleared the Request log.");

  await open(page, "config");
  await expect(page.locator("#config-view")).toContainText('"sources"');
  await page.locator("[data-action=config-toml]").click();
  await expect(page.locator("#config-view")).toContainText("[issuer.auth0]");
  await expect(page.locator("#config-view")).toContainText('client_secret = "***"');
  await page.locator("#config [data-action=reload]").click();
  await expect(page.locator("#config-out")).toContainText(/config files/);
  await open(page, "reset");
  await page.locator("#reset-form select[name=issuer]").selectOption("custom");
  await page.locator("#reset-form button[type=submit]").click();
  await expect(page.locator("#reset-out")).toContainText("Reset the runtime state of Issuer custom.");
});

test("Sign out shows the signed-out page with a link back", async ({ page }) => {
  await open(page);
  await page.locator('[data-issuer-row="auth0"]').getByRole("link", { name: "Sign out" }).click();
  await expect(page.locator("h1")).toHaveText("Signed out");
  await page.getByRole("link", { name: "dashboard" }).click();
  await expect(page).toHaveURL(`${MOCK}/_mock/`);
});

test("the sidebar marks one item and each item shows its view", async ({ page }) => {
  await open(page);
  const items = page.locator(".sidebar .nav-item");
  for (const view of await items.evaluateAll((all) => all.map((a) => (a as HTMLElement).dataset.view!))) {
    await page.locator(`.nav-item[data-view="${view}"]`).click();
    await expect(page.locator(`#${view}`)).toBeVisible();
    await expect(page.locator('.nav-item[aria-current="page"]')).toHaveCount(1);
    await expect(page.locator(`.nav-item[data-view="${view}"]`)).toHaveAttribute("aria-current", "page");
    // Hover must not paint the active background on a second item.
    const painted = await items.evaluateAll(
      (all) => all.filter((a) => getComputedStyle(a).backgroundColor !== "rgba(0, 0, 0, 0)").length,
    );
    expect(painted).toBe(1);
  }
});

/** Runs "Run login flow" in the Debugger frame and signs in `user` on the login page in the frame. */
async function loginInFrame(page: Page, user: string) {
  const frame = page.frameLocator("#debugger-frame");
  await frame.getByRole("link", { name: "Run login flow" }).click();
  await expect(frame.locator("h1")).toHaveText("Sign in");
  await frame.locator("select[name=user]").selectOption(user);
  await frame.getByRole("button", { name: "Sign in" }).click();
  // The callback page in the frame: the decoded tokens of the flow, without the page chrome.
  await expect(frame.locator("h2", { hasText: "id_token" })).toBeVisible();
  await expect(frame.locator("h2", { hasText: "access_token" })).toBeVisible();
  await expect(frame.locator(".label-success").first()).toHaveText("signature valid");
  await expect(frame.locator(".page-top")).toHaveCount(0);
  await expect(frame.locator(".page-foot")).toHaveCount(0);
  return frame;
}

test("the Debugger view runs the full login flow in the frame for two Issuers", async ({ page }) => {
  await open(page, "debugger");
  await expect(page).toHaveURL(`${MOCK}/_mock/#debugger/auth0`);
  const select = page.locator("#debugger-issuer");
  await expect(select).toHaveValue("auth0");
  const frameEl = page.locator("#debugger-frame");
  await expect(frameEl).toHaveAttribute("src", "/auth0/debugger?embed=1");
  await expect(page.getByRole("link", { name: "Open in new tab" })).toHaveAttribute("href", "/auth0/debugger");

  let frame = await loginInFrame(page, "alice");
  await expect(frame.locator("pre code").nth(1)).toContainText('"sub": "auth0|alice"');
  // The dashboard stays on the page; only the frame navigated.
  await expect(page).toHaveURL(`${MOCK}/_mock/#debugger/auth0`);

  // A second Issuer with other paths (okta: /oauth2/default/v1/authorize).
  await select.selectOption("okta");
  await expect(page).toHaveURL(`${MOCK}/_mock/#debugger/okta`);
  await expect(frameEl).toHaveAttribute("src", "/oauth2/default/debugger?embed=1");
  await expect(page.getByRole("link", { name: "Open in new tab" })).toHaveAttribute(
    "href",
    "/oauth2/default/debugger",
  );
  frame = await loginInFrame(page, "bob");
  await expect(frame.locator("pre code").nth(1)).toContainText("00ubob");

  // The fragment selects the Issuer on a new load.
  await page.goto(`${MOCK}/_mock/#debugger/okta`);
  await expect(page.locator("#debugger")).toBeVisible();
  await expect(select).toHaveValue("okta");
  await expect(page.frameLocator("#debugger-frame").locator(".label-pair")).toContainText("okta");
});

test("the debugger pages allow only same-origin frames; the dashboard allows none", async ({ request }) => {
  const dash = await request.get(`${MOCK}/_mock/`);
  expect(dash.headers()["x-frame-options"]).toBe("DENY");
  expect(dash.headers()["content-security-policy"]).toBe("frame-ancestors 'none'");
  for (const path of ["/auth0/debugger", "/auth0/debugger?embed=1", "/auth0/authorize?client_id=nobody&response_type=code"]) {
    const res = await request.get(`${MOCK}${path}`, { maxRedirects: 0 });
    expect(res.headers()["x-frame-options"], path).toBe("SAMEORIGIN");
    expect(res.headers()["content-security-policy"], path).toBe("frame-ancestors 'self'");
  }
});

test("the standalone debugger page keeps its brand row and footer", async ({ page }) => {
  await page.goto(`${MOCK}/auth0/debugger`);
  await expect(page).toHaveTitle(/Debugger/);
  await expect(page.locator(".page-top")).toBeVisible();
  await expect(page.locator(".page-foot")).toBeVisible();
});

test("the dashboard does not widen the page at 375 px", async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 720 });
  await open(page);
  await expect(page.locator(".sidebar")).toBeHidden();
  await page.locator("#nav-select").selectOption("users");
  await expect(page.locator("#users")).toBeVisible();
  await page.locator("#nav-select").selectOption("debugger");
  await expect(page.locator("#debugger")).toBeVisible();
  const { scrollWidth, clientWidth } = await page.evaluate(() => ({
    scrollWidth: document.scrollingElement!.scrollWidth,
    clientWidth: document.scrollingElement!.clientWidth,
  }));
  expect(scrollWidth).toBeLessThanOrEqual(clientWidth);
});
