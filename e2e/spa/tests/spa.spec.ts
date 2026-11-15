import { expect, test, type APIRequestContext, type Page } from "@playwright/test";

const MOCK = "http://localhost:9000";

type Spa = {
  name: string;
  url: string;
  tokenPath: string;
  endsessionPath: string;
};

const spas: Spa[] = [
  {
    name: "auth0-spa-js",
    url: "http://localhost:5173/",
    tokenPath: "/auth0/oauth/token",
    endsessionPath: "/auth0/v2/logout",
  },
  {
    name: "oidc-client-ts",
    url: "http://localhost:5174/",
    tokenPath: "/oauth2/default/v1/token",
    endsessionPath: "/oauth2/default/v1/logout",
  },
];

type LoggedRequest = { method: string; path: string; body: string; status: number };

async function requests(api: APIRequestContext, path: string): Promise<LoggedRequest[]> {
  const res = await api.get(`${MOCK}/_mock/requests?path=${encodeURIComponent(path)}`);
  expect(res.ok()).toBeTruthy();
  return (await res.json()) as LoggedRequest[];
}

function collectConsoleErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") errors.push(msg.text());
  });
  page.on("pageerror", (err) => errors.push(err.message));
  return errors;
}

for (const spa of spas) {
  test(`${spa.name}: log in, refresh and log out`, async ({ page, request }, testInfo) => {
    // 1. Clear the Request log and watch the console.
    const cleared = await request.delete(`${MOCK}/_mock/requests`);
    expect(cleared.status()).toBe(204);
    const errors = collectConsoleErrors(page);
    try {
      await steps(spa, page, request);
    } finally {
      await testInfo.attach("console-errors", { body: errors.join("\n"), contentType: "text/plain" });
      // A CORS failure shows only in the console. Soft, so it is reported
      // also when it made an earlier step fail.
      expect.soft(errors.filter((e) => e.includes("CORS") || e.includes("Cross-Origin")), "CORS errors in the console").toEqual([]);
    }
  });
}

async function steps(spa: Spa, page: Page, request: APIRequestContext) {
  // 2. Log in as alice on the mock login page.
  await page.goto(spa.url);
  await expect(page.locator("#status")).toHaveText("logged-out");
  await page.click("#login");
  await expect(page.locator("h1")).toHaveText("Sign in");
  await page.click("button[type=submit]");
  await expect(page.locator("#status")).toHaveText("logged-in:alice@example.com");

  // 3. Refresh with the refresh token grant, not a second login.
  const before = (await page.locator("#token").textContent()) ?? "";
  expect(before).not.toBe("");
  await page.click("#refresh");
  await expect(page.locator("#token")).not.toHaveText(before);
  const tokenCalls = await requests(request, spa.tokenPath);
  expect(
    tokenCalls.some(
      (r) => r.method === "POST" && r.status === 200 && r.body.includes("grant_type=refresh_token"),
    ),
    `refresh POST in ${JSON.stringify(tokenCalls.map((r) => [r.status, r.body]))}`,
  ).toBeTruthy();

  // 4. Log out through /endsession and land back on the SPA, logged out.
  await page.click("#logout");
  await page.waitForURL(spa.url);
  await expect(page.locator("#status")).toHaveText("logged-out");
  const logoutCalls = await requests(request, spa.endsessionPath);
  expect(
    logoutCalls.some((r) => r.status === 302),
    `logout redirect in ${JSON.stringify(logoutCalls.map((r) => r.status))}`,
  ).toBeTruthy();
}
