// Static server for the SPA exit test. Node built-ins only.
// Port 5173 serves the auth0-spa-js page, port 5174 the oidc-client-ts page.
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));

const libs = {
  "/lib/auth0-spa-js.js": "node_modules/@auth0/auth0-spa-js/dist/auth0-spa-js.production.js",
  "/lib/oidc-client-ts.js": "node_modules/oidc-client-ts/dist/browser/oidc-client-ts.js",
};

const sites = [
  { port: 5173, page: "auth0/index.html" },
  { port: 5174, page: "oidc/index.html" },
];

for (const { port, page } of sites) {
  createServer(async (req, res) => {
    const path = new URL(req.url ?? "/", "http://localhost").pathname;
    const file = path === "/" ? page : libs[path];
    if (req.method !== "GET" || !file) {
      res.writeHead(404, { "content-type": "text/plain" }).end("not found\n");
      return;
    }
    try {
      const body = await readFile(join(root, file));
      const type = file.endsWith(".html") ? "text/html; charset=utf-8" : "text/javascript; charset=utf-8";
      res.writeHead(200, { "content-type": type, "cache-control": "no-store" }).end(body);
    } catch {
      res.writeHead(404, { "content-type": "text/plain" }).end("not found\n");
    }
  }).listen(port, "localhost", () => {
    console.log(`serving ${page} on http://localhost:${port}/`);
  });
}
