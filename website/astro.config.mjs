// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightLinksValidator from 'starlight-links-validator';
import { docsDir, syncDocs } from './scripts/sync-docs.mjs';

// The docs pages come from the repo docs/ folder (scripts/sync-docs.mjs).
syncDocs();

const GITHUB = 'https://github.com/schmas/fauxidc';
const README = `${GITHUB}#readme`;

/** Writes the docs pages again when a file in docs/ changes during `astro dev`. */
const docsWatcher = {
  name: 'fauxidc-docs-watcher',
  hooks: {
    /** @param {{ server: import('vite').ViteDevServer }} options */
    'astro:server:setup': ({ server }) => {
      server.watcher.add(docsDir);
      const resync = (/** @type {string} */ file) => {
        if (file.startsWith(docsDir)) syncDocs({ quiet: true });
      };
      server.watcher.on('add', resync);
      server.watcher.on('change', resync);
      server.watcher.on('unlink', resync);
    },
  },
};

export default defineConfig({
  site: 'https://schmas.github.io',
  base: '/fauxidc',
  trailingSlash: 'always',
  integrations: [
    starlight({
      title: 'fauxidc',
      description:
        'fauxidc is an OAuth 2.0 / OpenID Connect mock server for local development and integration tests.',
      logo: { src: './src/assets/logo.svg', alt: '' },
      favicon: '/favicon.svg',
      customCss: ['./src/styles/halo.css'],
      social: [
        { icon: 'github', label: 'GitHub', href: GITHUB },
      ],
      lastUpdated: false,
      pagination: true,
      plugins: [starlightLinksValidator({ errorOnLocalLinks: false })],
      sidebar: [
        {
          label: 'Start',
          items: [
            { label: 'Overview', link: '/' },
            { label: 'Start in 60 seconds', link: `${GITHUB}#start-in-60-seconds`, attrs: { target: '_blank' } },
            { label: 'Comparison', link: '/comparison/' },
          ],
        },
        { label: 'Docs', items: [{ autogenerate: { directory: 'docs' } }] },
        {
          label: 'Recipes',
          items: [
            { label: 'SPA with PKCE', link: `${GITHUB}#spa-with-pkce`, attrs: { target: '_blank' } },
            { label: 'Backend with a client secret', link: `${GITHUB}#backend-with-a-client-secret`, attrs: { target: '_blank' } },
            { label: 'Machine-to-machine', link: `${GITHUB}#machine-to-machine`, attrs: { target: '_blank' } },
            { label: 'Mint a token in a test', link: `${GITHUB}#mint-a-token-in-a-test`, attrs: { target: '_blank' } },
            { label: 'Testcontainers', link: `${GITHUB}#random-host-port-testcontainers`, attrs: { target: '_blank' } },
            { label: 'Simulate a provider outage', link: `${GITHUB}#simulate-a-provider-outage`, attrs: { target: '_blank' } },
            { label: 'All recipes (README)', link: `${GITHUB}#recipes`, attrs: { target: '_blank' } },
          ],
        },
        { label: 'Architecture decisions', collapsed: true, items: [{ autogenerate: { directory: 'adr' } }] },
        {
          label: 'Project',
          items: [
            { label: 'README', link: README, attrs: { target: '_blank' } },
            { label: 'Releases', link: `${GITHUB}/releases`, attrs: { target: '_blank' } },
            { label: 'Changelog', link: `${GITHUB}/blob/main/CHANGELOG.md`, attrs: { target: '_blank' } },
            { label: 'Security', link: `${GITHUB}/blob/main/SECURITY.md`, attrs: { target: '_blank' } },
          ],
        },
      ],
    }),
    docsWatcher,
  ],
});
