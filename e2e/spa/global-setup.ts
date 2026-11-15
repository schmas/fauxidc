// Fails fast when Playwright would reuse a server on port 9000 that is not
// fauxidc with the example configs (see server-check.mjs).
import { checkPort9000 } from "./server-check.mjs";

export default async function globalSetup(): Promise<void> {
  // In CI, reuseExistingServer is off: Playwright starts its own server.
  if (process.env.CI) {
    return;
  }
  await checkPort9000();
}
