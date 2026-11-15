import { createHash, randomBytes } from "node:crypto";
import { expect, test, type Page } from "@playwright/test";

// The built-in login page in username mode: Issuer `custom` from custom-user.toml has
// `custom_user`, so "Other…" shows one username field. Uses the server that
// playwright.config.ts starts.

const MOCK = "http://localhost:9000";
const REDIRECT = "http://localhost:5173/";

function authorizeUrl(): { url: string; verifier: string } {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const q = new URLSearchParams({
    client_id: "example-spa",
    redirect_uri: REDIRECT,
    response_type: "code",
    scope: "openid profile email",
    state: "username-test",
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  return { url: `${MOCK}/custom/authorize?${q}`, verifier };
}

async function openLogin(page: Page): Promise<string> {
  const { url, verifier } = authorizeUrl();
  await page.goto(url);
  await expect(page.locator("h1")).toHaveText("Sign in");
  return verifier;
}

/** Page scroll sizes and the bottom of the "Sign in" button. */
async function layout(page: Page) {
  return page.evaluate(() => {
    const root = document.scrollingElement!;
    const button = document.querySelector("button[type=submit]")!.getBoundingClientRect();
    return {
      scrollWidth: root.scrollWidth,
      clientWidth: root.clientWidth,
      scrollHeight: root.scrollHeight,
      clientHeight: root.clientHeight,
      buttonBottom: button.bottom,
    };
  });
}

test("the username field shows only when Other… is selected", async ({ page }) => {
  await openLogin(page);
  await expect(page.locator("select[name=user] option[value=__custom__]")).toHaveText("Other…");
  const custom = page.locator("#custom-user");
  await expect(custom).toBeHidden();
  await page.selectOption("select[name=user]", "__custom__");
  await expect(custom).toBeVisible();
  await expect(page.locator("input[name=username]")).toBeVisible();
  await expect(page.locator("[name=custom_sub], [name=custom_claims]")).toHaveCount(0);
  await page.selectOption("select[name=user]", "alice");
  await expect(custom).toBeHidden();
});

test("an empty username marks only the username field", async ({ page }) => {
  await openLogin(page);
  await page.selectOption("select[name=user]", "__custom__");
  await page.fill("input[name=username]", "   ");
  await page.click("button[type=submit]");
  await expect(page.locator("[role=alert]")).toContainText("Enter a username");
  await expect(page.locator("[aria-invalid=true]")).toHaveCount(1);
  await expect(page.locator("input[name=username]")).toHaveAttribute("aria-invalid", "true");
});

test.describe("without JavaScript", () => {
  test.use({ javaScriptEnabled: false });

  test("the username flow works and builds the User", async ({ page, request }) => {
    const verifier = await openLogin(page);
    await expect(page.locator("#custom-user")).toBeVisible();
    await expect(page.locator("#custom-user legend")).toContainText("only for Other…");
    await page.selectOption("select[name=user]", "__custom__");
    await page.fill("input[name=username]", "  Carol ");
    await page.click("button[type=submit]");
    await page.waitForURL((url) => url.href.startsWith(REDIRECT) && url.searchParams.has("code"));
    const code = new URL(page.url()).searchParams.get("code")!;
    const response = await request.post(`${MOCK}/custom/token`, {
      form: {
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT,
        client_id: "example-spa",
        code_verifier: verifier,
      },
    });
    expect(response.status()).toBe(200);
    const idToken: string = (await response.json()).id_token;
    const claims = JSON.parse(Buffer.from(idToken.split(".")[1], "base64url").toString());
    expect(claims.sub).toBe("carol");
    expect(claims.email).toBe("carol@example.test");
    expect(claims.name).toBe("carol Example");
  });
});

for (const width of [375, 1280]) {
  test(`username mode has no horizontal scroll at ${width} px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 720 });
    await openLogin(page);
    await page.selectOption("select[name=user]", "__custom__");
    let box = await layout(page);
    expect(box.scrollWidth).toBe(box.clientWidth);
    // With the error alert too.
    await page.click("button[type=submit]");
    await expect(page.locator("[role=alert]")).toContainText("Enter a username");
    box = await layout(page);
    expect(box.scrollWidth).toBe(box.clientWidth);
  });
}

for (const [width, height] of [
  [1280, 720],
  [1440, 900],
]) {
  test(`username mode has no page scroll at ${width}x${height}`, async ({ page }) => {
    await page.setViewportSize({ width, height });
    await openLogin(page);
    await page.selectOption("select[name=user]", "__custom__");
    await page.click("button[type=submit]");
    await expect(page.locator("[role=alert]")).toContainText("Enter a username");
    await page.locator("details summary").click();
    const box = await layout(page);
    expect(box.scrollHeight).toBe(box.clientHeight);
    expect(box.buttonBottom).toBeLessThanOrEqual(height);
  });
}
