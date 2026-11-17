import { createHash, randomBytes } from "node:crypto";
import { expect, test, type Page } from "@playwright/test";

// The built-in login page: the default Custom user form, the switch "Choose a configured User",
// the saved view and the page without JavaScript.
// Uses the auth0 example server that playwright.config.ts starts.

const MOCK = "http://localhost:9000";
const REDIRECT = "http://localhost:5173/";

function authorizeUrl(): string {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const q = new URLSearchParams({
    client_id: "example-spa",
    redirect_uri: REDIRECT,
    response_type: "code",
    scope: "openid profile email",
    state: "login-page-test",
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  return `${MOCK}/auth0/authorize?${q}`;
}

async function openLogin(page: Page) {
  await page.goto(authorizeUrl());
  await expect(page.locator("h1")).toHaveText("Sign in");
}

test("the default view shows Subject and Claims, not the User dropdown", async ({ page }) => {
  await openLogin(page);
  await expect(page.locator("#custom-user")).toBeVisible();
  await expect(page.locator("input[name=custom_sub]")).toBeVisible();
  await expect(page.locator("textarea[name=custom_claims]")).toBeVisible();
  await expect(page.locator("#user-list")).toBeHidden();
  await expect(page.locator("#f-show-users")).not.toBeChecked();
  await expect(page.locator("select[name=user] option[value=__custom__]")).toHaveCount(0);
});

test("the switch shows the User dropdown and signs in a User", async ({ page }) => {
  await openLogin(page);
  await page.locator("#f-show-users").check();
  await expect(page.locator("#user-list")).toBeVisible();
  await expect(page.locator("#custom-user")).toBeHidden();
  await expect(page.locator("select[name=user] option[value=__custom__]")).toHaveCount(0);
  await page.selectOption("select[name=user]", "alice");
  await page.locator("#f-show-users").uncheck();
  await expect(page.locator("#custom-user")).toBeVisible();
  await expect(page.locator("#user-list")).toBeHidden();
  await page.locator("#f-show-users").check();
  await page.click("button[type=submit]");
  await page.waitForURL((url) => url.href.startsWith(REDIRECT) && url.searchParams.has("code"));
});

test("a reload keeps the view and shows that it is saved", async ({ page }) => {
  await openLogin(page);
  await page.locator("#f-show-users").check();
  await expect(page.locator("#f-show-users-note")).toContainText("Saved in this browser");
  await page.goto(authorizeUrl());
  await expect(page.locator("#user-list")).toBeVisible();
  await expect(page.locator("#f-show-users")).toBeChecked();
  await expect(page.locator("#custom-user")).toBeHidden();
  await expect(page.locator("#f-show-users-note")).toContainText("Saved in this browser");
});

test("endsession clears the saved view and the page is back on the form", async ({ page }) => {
  await openLogin(page);
  await page.locator("#f-show-users").check();
  await page.goto(`${MOCK}/auth0/v2/logout`);
  await openLogin(page);
  await expect(page.locator("#custom-user")).toBeVisible();
  await expect(page.locator("#user-list")).toBeHidden();
  await expect(page.locator("#f-show-users")).not.toBeChecked();
});

test.describe("without JavaScript", () => {
  test.use({ javaScriptEnabled: false });

  test("login page without JavaScript shows the Custom user form", async ({ page }) => {
    await openLogin(page);
    await expect(page.locator("#custom-user")).toBeVisible();
    await expect(page.locator("#user-list")).toBeHidden();
    await page.fill("input[name=custom_sub]", "carol");
    await page.click("button[type=submit]");
    await page.waitForURL((url) => url.href.startsWith(REDIRECT) && url.searchParams.has("code"));
    expect(new URL(page.url()).searchParams.get("state")).toBe("login-page-test");
  });
});

for (const width of [375, 1280]) {
  test(`a long error message does not widen the page at ${width} px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 720 });
    const long = `http://x/${"a".repeat(600)}`;
    const q = new URLSearchParams({ client_id: "example-spa", redirect_uri: long, response_type: "code" });
    await page.goto(`${MOCK}/auth0/authorize?${q}`);
    await expect(page.locator("[role=alert]")).toContainText("redirect_uri");
    const { scrollWidth, clientWidth } = await page.evaluate(() => ({
      scrollWidth: document.scrollingElement!.scrollWidth,
      clientWidth: document.scrollingElement!.clientWidth,
    }));
    expect(scrollWidth).toBe(clientWidth);
  });
}
