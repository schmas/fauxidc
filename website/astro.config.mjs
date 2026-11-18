// @ts-check
import fs from 'node:fs';
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightLinksValidator from 'starlight-links-validator';
import { docsDir, syncDocs } from './scripts/sync-docs.mjs';

const GITHUB = 'https://github.com/schmas/fauxidc';
const README = `${GITHUB}#readme`;

// The docs pages come from the repo docs/ folder (scripts/sync-docs.mjs).
const pages = syncDocs();

// The "Recipes" group links each `##` section of docs/recipes.md.
const recipes = pages.find((p) => p.source === 'docs/recipes.md');
const recipeItems = recipes
  ? [
      { label: 'All recipes', link: recipes.route },
      ...recipes.headings.map((h) => ({ label: h.text, link: `${recipes.route}#${h.slug}` })),
    ]
  : [{ label: 'Recipes (README)', link: README, attrs: { target: '_blank' } }];

/** Fails the build if a "Recipes" sidebar link points to a heading that does not exist. */
const recipeAnchorCheck = {
  name: 'fauxidc-recipe-anchor-check',
  hooks: {
    /** @param {{ dir: URL }} options */
    'astro:build:done': ({ dir }) => {
      if (!recipes) return;
      const html = fs.readFileSync(new URL(`.${recipes.route}index.html`, dir), 'utf8');
      const missing = recipes.headings.filter((h) => !html.includes(`id="${h.slug}"`));
      if (missing.length > 0) {
        throw new Error(`Recipes sidebar: no heading for ${missing.map((h) => `#${h.slug}`).join(', ')}`);
      }
    },
  },
};

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
  site: 'https://fauxidc.schmas.com',
  trailingSlash: 'always',
  integrations: [
    starlight({
      title: 'fauxidc',
      description:
        'fauxidc is an OAuth 2.0 / OpenID Connect mock server for local development and integration tests.',
      logo: { src: './src/assets/logo.svg', alt: '' },
      favicon: '/favicon.svg',
      customCss: ['./src/styles/halo.css'],
      components: {
        SiteTitle: './src/components/SiteTitle.astro',
        SocialIcons: './src/components/SocialIcons.astro',
      },
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
            { label: 'Start in 60 seconds', link: '/#start-in-60-seconds' },
            { label: 'Comparison', link: '/comparison/' },
          ],
        },
        { label: 'Docs', items: [{ autogenerate: { directory: 'docs' } }] },
        { label: 'Recipes', items: recipeItems },
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
    recipeAnchorCheck,
  ],
});
