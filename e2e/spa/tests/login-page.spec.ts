import { createHash, randomBytes } from "node:crypto";
import { expect, test, type Page } from "@playwright/test";

// The built-in login page: the Custom user fields with and without JavaScript.
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

test("Custom fields show only when Custom… is selected", async ({ page }) => {
  await openLogin(page);
  const custom = page.locator("#custom-user");
  await expect(custom).toBeHidden();
  await page.selectOption("select[name=user]", "__custom__");
  await expect(custom).toBeVisible();
  await expect(page.locator("input[name=custom_sub]")).toBeVisible();
  await page.selectOption("select[name=user]", "alice");
  await expect(custom).toBeHidden();
});

test.describe("without JavaScript", () => {
  test.use({ javaScriptEnabled: false });

  test("login page without JavaScript shows the Custom fields", async ({ page }) => {
    await openLogin(page);
    await expect(page.locator("#custom-user")).toBeVisible();
    await page.selectOption("select[name=user]", "__custom__");
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
