// Checks port 9000 before the SPA exit test. If a server answers there but it
// is not fauxidc with examples/auth0.toml, examples/okta.toml and custom-user.toml, the check
// fails, so the tests never run against another server.
//
// Two callers: global-setup.ts (when Playwright reuses a running server) and
// the webServer command (when Playwright starts fauxidc itself):
//   node server-check.mjs && cargo run ...
import { pathToFileURL } from "node:url";

const EXPECTED = [
  // examples/auth0.toml
  ["http://localhost:9000/auth0/.well-known/openid-configuration", "http://localhost:9000/auth0/"],
  // examples/okta.toml
  ["http://localhost:9000/oauth2/default/.well-known/openid-configuration", "http://localhost:9000/oauth2/default"],
  // custom-user.toml
  ["http://localhost:9000/custom/.well-known/openid-configuration", "http://localhost:9000/custom/"],
];

export const MESSAGE =
  "port 9000 has a server that is not fauxidc with examples/auth0.toml, examples/okta.toml and e2e/spa/custom-user.toml; stop it or free the port";

/** The issuer of a discovery answer, `null` for another answer or no answer in 5 s, `undefined` when nothing listens. */
async function issuerAt(url) {
  let response;
  try {
    response = await fetch(url, { signal: AbortSignal.timeout(5_000) });
  } catch (error) {
    // A server that accepts the connection but does not answer is not fauxidc.
    if (error?.name === "TimeoutError") {
      return null;
    }
    return undefined;
  }
  if (response.status !== 200) {
    return null;
  }
  try {
    const body = await response.json();
    return typeof body.issuer === "string" ? body.issuer : null;
  } catch {
    return null;
  }
}

/** Resolves when nothing answers on port 9000 or when fauxidc with the example configs answers. */
export async function checkPort9000() {
  const answers = await Promise.all(EXPECTED.map(([url]) => issuerAt(url)));
  if (answers.every((answer) => answer === undefined)) {
    return;
  }
  if (!answers.every((answer, i) => answer === EXPECTED[i][1])) {
    throw new Error(MESSAGE);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  checkPort9000().catch((error) => {
    console.error(`error: ${error.message}`);
    process.exit(1);
  });
}
