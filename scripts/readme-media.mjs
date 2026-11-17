// Captures the browser media of the README: screenshots and GIFs of the login page,
// the debugger and the dashboard. scripts/readme-media.sh starts fauxidc with
// docs/media/fauxidc.toml and then runs this script. Do not run it alone.
//
// Usage: node scripts/readme-media.mjs <output directory>
// The pages use http://localhost:9000. If FAUXIDC_MEDIA_PORT names another port, the browser
// and the Test API calls go to that port, but the pages keep the URLs of port 9000.
// Needs Playwright (e2e/spa/node_modules), ffmpeg and, if available, gifski.
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(join(root, "e2e/spa/package.json"));
const { chromium } = require("@playwright/test");

const [OUT] = process.argv.slice(2);
const MOCK = "http://localhost:9000";
const PORT = process.env.FAUXIDC_MEDIA_PORT || "9000";
const SERVER = `http://localhost:${PORT}`;
if (!OUT) {
  console.error("usage: node scripts/readme-media.mjs <output directory>");
  process.exit(2);
}
mkdirSync(OUT, { recursive: true });
const ISSUER = `${MOCK}/example`;
const APP_PORT = 5180;
const APP = `http://localhost:${APP_PORT}/`;
// One viewport for every capture, light theme.
const VIEWPORT = { width: 1280, height: 800 };
const GIF_WIDTH = 800;
const GIF_FPS = 10;

// The demo app: one page with a code flow and PKCE, no library.
const appPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>example-app</title>
<style>
  body { font: 16px/1.5 system-ui, sans-serif; margin: 0; background: #f5f6fa; color: #1d2433; }
  header { background: #283044; color: #fff; padding: 14px 32px; font-weight: 600; }
  main { max-width: 640px; margin: 40px auto; background: #fff; border-radius: 10px; padding: 28px 32px;
         box-shadow: 0 1px 4px rgba(0, 0, 0, .12); }
  h1 { font-size: 22px; margin: 0 0 12px; }
  button { font: inherit; background: #3b5bdb; color: #fff; border: 0; border-radius: 6px; padding: 8px 18px; cursor: pointer; }
  table { border-collapse: collapse; margin: 16px 0; width: 100%; }
  td { border-top: 1px solid #e3e6ee; padding: 6px 8px; font-family: ui-monospace, monospace; font-size: 14px; }
  td:first-child { color: #5c667a; width: 30%; }
  .error { background: #fdecec; color: #a12222; border-radius: 6px; padding: 12px 14px; font-family: ui-monospace, monospace; font-size: 14px; }
</style>
</head>
<body>
<header>example-app</header>
<main id="main"><h1>Welcome</h1><p>Loading…</p></main>
<script>
const ISSUER = ${JSON.stringify(ISSUER)};
const CLIENT = "example-app";
const REDIRECT = ${JSON.stringify(APP)};
const main = document.getElementById("main");

function b64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
}
function claimsOf(jwt) {
  const part = jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
  return JSON.parse(atob(part));
}
function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
}
function loggedOut(extra) {
  main.innerHTML = '<h1>Welcome</h1><p>You are not signed in.</p>' + (extra || "") +
    '<p><button id="login">Log in</button></p>';
  document.getElementById("login").onclick = login;
}
async function login() {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  sessionStorage.setItem("verifier", verifier);
  const q = new URLSearchParams({
    client_id: CLIENT, redirect_uri: REDIRECT, response_type: "code",
    scope: "openid profile email", state: "readme", code_challenge: b64url(digest), code_challenge_method: "S256",
  });
  location.href = ISSUER + "/authorize?" + q;
}
async function callback(code) {
  history.replaceState({}, "", "/");
  const res = await fetch(ISSUER + "/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code", code, redirect_uri: REDIRECT, client_id: CLIENT,
      code_verifier: sessionStorage.getItem("verifier") || "",
    }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    loggedOut('<p class="error" id="error">Login failed: POST /token returned ' + res.status + "<br>" +
      esc(body.error || "") + ": " + esc(body.error_description || "") + "</p>");
    return;
  }
  const c = claimsOf(body.id_token);
  const rows = ["sub", "name", "email", "roles", "iss"].map((k) =>
    "<tr><td>" + k + "</td><td>" + esc(JSON.stringify(c[k])) + "</td></tr>").join("");
  main.innerHTML = '<h1 id="welcome">Hello, ' + esc(c.name) + "</h1><p>Signed in with fauxidc. ID token claims:</p>" +
    "<table>" + rows + "</table>";
}
const code = new URLSearchParams(location.search).get("code");
if (code) callback(code); else loggedOut();
</script>
</body>
</html>
`;

// A visible cursor: Playwright videos do not show the mouse.
const cursorScript = () => {
  window.addEventListener("DOMContentLoaded", () => {
    const dot = document.createElement("div");
    dot.id = "readme-cursor";
    Object.assign(dot.style, {
      position: "fixed", left: "-40px", top: "-40px", width: "18px", height: "18px", marginLeft: "-9px", marginTop: "-9px",
      borderRadius: "50%", background: "rgba(220, 38, 38, .45)", border: "2px solid rgba(220, 38, 38, .9)",
      pointerEvents: "none", zIndex: "2147483647", transition: "transform .1s",
    });
    document.documentElement.appendChild(dot);
    const last = sessionStorage.getItem("readme-cursor");
    if (last) [dot.style.left, dot.style.top] = last.split(",");
    document.addEventListener("mousemove", (e) => {
      dot.style.left = `${e.clientX}px`;
      dot.style.top = `${e.clientY}px`;
      sessionStorage.setItem("readme-cursor", `${dot.style.left},${dot.style.top}`);
    });
    document.addEventListener("mousedown", () => (dot.style.transform = "scale(.7)"));
    document.addEventListener("mouseup", () => (dot.style.transform = ""));
  });
};

function startApp() {
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      const path = new URL(req.url ?? "/", APP).pathname;
      if (req.method !== "GET" || path !== "/") {
        res.writeHead(404, { "content-type": "text/plain" }).end("not found\n");
        return;
      }
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" }).end(appPage);
    });
    server.listen(APP_PORT, "localhost", () => resolve(server));
  });
}

const pause = (page, ms) => page.waitForTimeout(ms);

/** Moves the visible cursor to the element, then clicks it. */
async function click(page, locator) {
  await locator.scrollIntoViewIfNeeded();
  const box = await locator.boundingBox();
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 12 });
  await pause(page, 250);
  await locator.click();
}

async function newContext(browser, video) {
  const options = { viewport: VIEWPORT, colorScheme: "light", deviceScaleFactor: 1, locale: "en-US" };
  if (video) options.recordVideo = { dir: video, size: VIEWPORT };
  const context = await browser.newContext(options);
  if (SERVER !== MOCK) {
    // Send the requests for port 9000 to the server on the other port.
    await context.route(`${MOCK}/**`, (route) => route.continue({ url: route.request().url().replace(MOCK, SERVER) }));
  }
  if (video) await context.addInitScript(cursorScript);
  return context;
}

/** Writes a PNG with a 256-color palette: small files, same look. */
function savePng(raw, name) {
  const tmp = join(OUT, `.${name}.raw.png`);
  writeFileSync(tmp, raw);
  execFileSync("ffmpeg", ["-loglevel", "error", "-y", "-i", tmp, "-vf",
    "split[a][b];[a]palettegen=max_colors=256:stats_mode=full[p];[b][p]paletteuse=dither=none", join(OUT, name)]);
  rmSync(tmp);
}

function hasGifski() {
  try {
    execFileSync("gifski", ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

/** Converts a Playwright video to a GIF: gifski when installed, else the ffmpeg palette filters. */
function toGif(webm, name) {
  const gif = join(OUT, name);
  const scale = `fps=${GIF_FPS},scale=${GIF_WIDTH}:-1:flags=lanczos`;
  if (hasGifski()) {
    const frames = mkdtempSync(join(tmpdir(), "readme-frames-"));
    execFileSync("ffmpeg", ["-loglevel", "error", "-y", "-i", webm, "-vf", scale, join(frames, "f%04d.png")]);
    const list = readdirSync(frames).sort().map((f) => join(frames, f));
    execFileSync("gifski", ["--quiet", "--fps", String(GIF_FPS), "--quality", "100", "--width", String(GIF_WIDTH), "-o", gif, ...list]);
    rmSync(frames, { recursive: true });
  } else {
    execFileSync("ffmpeg", ["-loglevel", "error", "-y", "-i", webm, "-vf",
      `${scale},split[a][b];[a]palettegen=max_colors=128[p];[b][p]paletteuse=dither=bayer:bayer_scale=4`, gif]);
  }
  console.log(`wrote ${name} (${Math.round(statSync(gif).size / 1024)} KiB)`);
}

/** Runs `steps` in a new recorded page and converts the video to `name`. */
async function record(browser, name, steps) {
  const dir = mkdtempSync(join(tmpdir(), "readme-video-"));
  const context = await newContext(browser, dir);
  const page = await context.newPage();
  await steps(page);
  const video = page.video();
  await context.close();
  toGif(await video.path(), name);
  rmSync(dir, { recursive: true });
}

async function api(path, method, body) {
  const res = await fetch(`${SERVER}${path}`, {
    method,
    headers: body ? { "content-type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`${method} ${path}: ${res.status}`);
  return res.status === 204 ? null : res.json();
}

async function screenshots(browser) {
  const context = await newContext(browser);
  const page = await context.newPage();

  // Login page, opened from the demo app.
  await page.goto(APP);
  await page.locator("#login").click();
  await page.locator("h1", { hasText: "Sign in" }).waitFor();
  await page.locator("input[name=custom_sub]").fill("dana");
  savePng(await page.screenshot(), "login-page.png");

  // Debugger with a decoded token from the Test API.
  const { access_token } = await api("/_mock/example/token", "POST", { user: "alice" });
  await page.goto(`${ISSUER}/debugger`);
  await page.locator("#f-token").fill(access_token);
  await page.getByRole("button", { name: "Decode" }).click();
  const decoded = page.locator("h2", { hasText: "Decoded" });
  await decoded.waitFor();
  await decoded.evaluate((el) => el.scrollIntoView({ block: "start" }));
  savePng(await page.screenshot(), "debugger.png");

  // Dashboard home.
  await page.goto(`${MOCK}/_mock/`);
  await page.locator(`[data-issuer-row="example"]`).waitFor();
  savePng(await page.screenshot(), "dashboard.png");
  await context.close();
}

async function loginFlow(page) {
  await page.goto(APP);
  await page.mouse.move(VIEWPORT.width / 2, VIEWPORT.height - 80);
  await pause(page, 900);
  await click(page, page.locator("#login"));
  await page.locator("h1", { hasText: "Sign in" }).waitFor();
  await pause(page, 1200);
  await click(page, page.locator("#f-show-users"));
  await pause(page, 700);
  const select = page.locator("select[name=user]");
  await click(page, select);
  await select.selectOption("bob");
  await pause(page, 500);
  await select.selectOption("alice");
  await pause(page, 800);
  await click(page, page.locator("button[type=submit]"));
  await page.locator("#welcome").waitFor();
  await pause(page, 2500);
}

async function failureFlow(page) {
  await page.goto(`${MOCK}/_mock/`);
  await page.locator(`[data-issuer-row="example"]`).waitFor();
  await page.mouse.move(VIEWPORT.width / 2, VIEWPORT.height / 2);
  await pause(page, 800);
  await click(page, page.locator('.nav-item[data-view="failures"]'));
  await pause(page, 700);
  const form = page.locator("#fail-form");
  await form.locator("select[name=issuer]").selectOption("example");
  await form.locator("select[name=endpoint]").selectOption("token");
  await click(page, form.locator("input[name=status]"));
  await form.locator("input[name=status]").pressSequentially("503", { delay: 120 });
  await pause(page, 400);
  await click(page, form.locator("button[type=submit]"));
  await page.locator("#fail-out").getByText("token request").first().waitFor();
  await pause(page, 1500);
  await page.goto(APP);
  await pause(page, 700);
  await click(page, page.locator("#login"));
  await page.locator("h1", { hasText: "Sign in" }).waitFor();
  await pause(page, 600);
  await click(page, page.locator("#f-show-users"));
  await pause(page, 500);
  await click(page, page.locator("button[type=submit]"));
  await page.locator("#error").waitFor();
  await page.mouse.move(VIEWPORT.width / 2, VIEWPORT.height - 60, { steps: 8 });
  await pause(page, 3000);
}

const app = await startApp();
const browser = await chromium.launch();
try {
  await screenshots(browser);
  await record(browser, "login-flow.gif", loginFlow);
  await api("/_mock/example/fail-next", "DELETE");
  await record(browser, "inject-failure.gif", failureFlow);
  await api("/_mock/example/fail-next", "DELETE");
} finally {
  await browser.close();
  app.close();
}
