// Builds the Starlight docs pages from the repo `docs/` folder.
//
// The repo `docs/` folder is the single source of truth. This script copies each
// Markdown file into a git-ignored folder under `src/content/docs/` and changes it
// for the site:
//
// - The first `# H1` becomes the page title. The script removes it from the body.
// - A link to another site page (`docs/x.md`) goes to that page. The `#anchor` stays.
// - A link to another repo file (`../README.md`, `../schema/...`, a skipped doc)
//   goes to the file on GitHub.
// - A leading "fauxidc: " in the title is removed (the site name is already fauxidc).
// - The images in `docs/media/` are copied to `public/media/`. A link into it goes to the copy.
//   Other files there (for example `.toml` or `.tape` sources) are not published.
// - `src/generated/site-data.json` lists the pages, their `##` headings and the images.
//   The alt text of an image comes from its first use in the repo README.md.
//   It also has the measured numbers of docs/footprint.md, so the landing page cannot drift.
//
// astro.config.mjs runs this script before each build and dev start. Run it by hand
// with `npm run sync`.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const websiteDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const repoDir = path.resolve(websiteDir, '..');
// FAUXIDC_DOCS_DIR replaces docs/, to test the site with other docs.
export const docsDir = process.env.FAUXIDC_DOCS_DIR
  ? path.resolve(process.env.FAUXIDC_DOCS_DIR)
  : path.join(repoDir, 'docs');

export const BASE = '/fauxidc';
const GITHUB = 'https://github.com/schmas/fauxidc';

// Generated output. All of these paths are in .gitignore.
const contentDir = path.join(websiteDir, 'src', 'content', 'docs');
export const OUTPUT_DIRS = {
  docs: path.join(contentDir, 'docs'),
  adr: path.join(contentDir, 'adr'),
  media: path.join(websiteDir, 'public', 'media'),
  data: path.join(websiteDir, 'src', 'generated'),
};

// Paths under docs/ that the site does not show. Links to them go to GitHub.
const SKIP = ['testing', 'media', 'releasing.md'];

// The sidebar order of the known pages. Other pages come after them, by name.
const ORDER = ['configuration', 'agents', 'recipes', 'features', 'test-api', 'templates', 'testcontainers', 'footprint'];
const LAST = ['spec'];
// Pages that the "Docs" sidebar group does not list, because another group links them.
const HIDDEN = ['recipes'];
// Shorter sidebar labels than the page titles.
const LABELS = { agents: 'Use with an AI coding agent' };

/** Returns the docs/ files the site shows, as paths relative to docs/ with `/`. */
function listDocs(dir = docsDir, rel = '') {
  if (!fs.existsSync(dir)) return [];
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const relPath = rel ? `${rel}/${entry.name}` : entry.name;
    if (entry.name.startsWith('.') || SKIP.includes(relPath)) continue;
    if (entry.isDirectory()) out.push(...listDocs(path.join(dir, entry.name), relPath));
    else if (entry.name.endsWith('.md')) out.push(relPath);
  }
  return out.sort();
}

/** Site route (without BASE) of a docs/ file, for example `adr/0001-x.md` -> `/adr/0001-x/`. */
function routeOf(relPath) {
  const slug = relPath.replace(/\.md$/, '').toLowerCase();
  return slug.startsWith('adr/') ? `/${slug}/` : `/docs/${slug}/`;
}

/** Output file of a docs/ file. */
function outputOf(relPath) {
  const slug = relPath.replace(/\.md$/, '');
  return slug.startsWith('adr/')
    ? path.join(OUTPUT_DIRS.adr, `${slug.slice(4)}.md`)
    : path.join(OUTPUT_DIRS.docs, `${slug}.md`);
}

/**
 * Rewrites one link target of the file `fromRel` (relative to docs/).
 * Returns the target unchanged when it is absolute or only an anchor.
 */
function rewriteTarget(target, fromRel, pages) {
  if (/^[a-z][a-z0-9+.-]*:/i.test(target) || target.startsWith('#') || target.startsWith('/')) {
    return target;
  }
  const hashAt = target.indexOf('#');
  const file = hashAt === -1 ? target : target.slice(0, hashAt);
  const anchor = hashAt === -1 ? '' : target.slice(hashAt);
  const fromDir = path.posix.dirname(`docs/${fromRel}`);
  const repoPath = path.posix.normalize(path.posix.join(fromDir, file));
  if (repoPath.startsWith('..')) return target; // Outside the repo: leave it.
  const docsRel = repoPath.startsWith('docs/') ? repoPath.slice(5) : null;
  if (docsRel && pages.has(docsRel)) return `${BASE}${routeOf(docsRel)}${anchor}`;
  if (docsRel && docsRel.startsWith('media/') && fs.existsSync(path.join(docsDir, docsRel))) {
    return `${BASE}/${docsRel}${anchor}`;
  }
  const isDir = file.endsWith('/') || isDirectory(path.join(repoDir, repoPath));
  const kind = isDir ? 'tree' : 'blob';
  return `${GITHUB}/${kind}/main/${repoPath.replace(/\/$/, '')}${anchor}`;
}

function isDirectory(p) {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
}

/** Rewrites the inline links, images and link definitions outside of code. */
function rewriteLinks(body, fromRel, pages) {
  const fix = (t) => rewriteTarget(t, fromRel, pages);
  let fence = null;
  return body
    .split('\n')
    .map((line) => {
      const fenceMatch = line.match(/^\s*(`{3,}|~{3,})/);
      if (fenceMatch) {
        if (!fence) fence = fenceMatch[1];
        else if (fenceMatch[1].startsWith(fence)) fence = null;
        return line;
      }
      if (fence) return line;
      const def = line.match(/^(\s{0,3}\[[^\]]+\]:\s*)(<[^>]*>|\S+)(.*)$/);
      if (def) {
        const raw = def[2].replace(/^<|>$/g, '');
        return `${def[1]}${fix(raw)}${def[3]}`;
      }
      // Split on inline code spans; change only the parts outside them.
      return line
        .split(/(`+[^`]*`+)/)
        .map((part, i) =>
          i % 2 === 1
            ? part
            : part
                .replace(/\]\(<([^>]*)>((?:\s+"[^"]*")?)\)/g, (_, t, title) => `](${fix(t)}${title})`)
                .replace(/\]\(([^)\s]+)((?:\s+"[^"]*")?)\)/g, (_, t, title) => `](${fix(t)}${title})`)
                .replace(/(<(?:img|a)\b[^>]*?\s(?:src|href)=")([^"]+)(")/g, (_, a, t, b) => `${a}${fix(t)}${b}`),
        )
        .join('');
    })
    .join('\n');
}

/** Removes the first `# H1` and returns it as plain text (no backticks or emphasis). */
function takeTitle(text, relPath) {
  const lines = text.replace(/^﻿/, '').split('\n');
  const at = lines.findIndex((l) => /^#\s+\S/.test(l));
  if (at === -1) return { title: path.posix.basename(relPath, '.md'), body: text };
  const title = lines[at]
    .replace(/^#\s+/, '')
    .replace(/\s+#*\s*$/, '')
    .replace(/[`*_]/g, '')
    .trim()
    .replace(/^fauxidc:\s+/i, '')
    .replace(/^./, (c) => c.toUpperCase());
  lines.splice(at, 1);
  if (lines[at] !== undefined && lines[at].trim() === '') lines.splice(at, 1);
  return { title, body: lines.join('\n') };
}

/** Returns the first plain paragraph line, as the page description. */
function takeDescription(body) {
  for (const line of body.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    if (/^(#|```|~~~|\||>|-|\*|\d+\.|<|!\[|Date:|Status:)/.test(t)) continue;
    const plain = t.replace(/\[([^\]]*)\]\([^)]*\)/g, '$1').replace(/[`*_]/g, '');
    return plain.length > 200 ? `${plain.slice(0, 197)}...` : plain;
  }
  return undefined;
}

function sidebarOrder(relPath) {
  const slug = relPath.replace(/\.md$/, '');
  if (ORDER.includes(slug)) return ORDER.indexOf(slug) + 1;
  if (LAST.includes(slug)) return 900 + LAST.indexOf(slug);
  return 100;
}

const IMAGE = /\.(png|gif|svg|jpe?g|webp)$/i;

/** Copies the image files of a folder (not its subfolders). */
function copyImages(from, to) {
  for (const entry of fs.readdirSync(from, { withFileTypes: true })) {
    if (entry.name.startsWith('.') || !entry.isFile() || !IMAGE.test(entry.name)) continue;
    fs.mkdirSync(to, { recursive: true });
    fs.copyFileSync(path.join(from, entry.name), path.join(to, entry.name));
  }
}

/** GitHub heading slug (the same as github-slugger for plain headings). */
export function slug(text) {
  return text
    .replace(/<[^>]*>/g, '')
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/[`*]/g, '')
    .trim()
    .toLowerCase()
    .replace(/[^\p{L}\p{M}\p{N}\p{Pc} -]/gu, '')
    .replace(/ /g, '-');
}

/** Returns the `##` headings outside of code, as `{ text, slug }`. */
function headingsOf(body) {
  const out = [];
  let fence = null;
  for (const line of body.split('\n')) {
    const f = line.match(/^\s*(`{3,}|~{3,})/);
    if (f) {
      if (!fence) fence = f[1];
      else if (f[1].startsWith(fence)) fence = null;
      continue;
    }
    const h = !fence && line.match(/^##\s+(.+?)\s*#*\s*$/);
    if (h) out.push({ text: h[1].replace(/[`*]/g, ''), slug: slug(h[1]) });
  }
  return out;
}

/** Image alt texts from README.md: `{ 'login-page.png': 'The login page ...' }`. */
function readmeAltTexts() {
  const readme = path.join(repoDir, 'README.md');
  const alts = {};
  if (!fs.existsSync(readme)) return alts;
  const text = fs.readFileSync(readme, 'utf8');
  const add = (alt, src) => {
    const m = src.match(/(?:^|\/)docs\/media\/([^/?#]+)$/);
    if (m && alt && !(m[1] in alts)) alts[m[1]] = alt;
  };
  for (const m of text.matchAll(/!\[([^\]]*)\]\(([^)\s]+)\)/g)) add(m[1], m[2]);
  for (const m of text.matchAll(/<img\b[^>]*>/g)) {
    const src = m[0].match(/\ssrc="([^"]+)"/);
    const alt = m[0].match(/\salt="([^"]*)"/);
    if (src && alt) add(alt[1], src[1]);
  }
  return alts;
}

/**
 * Reads the measured numbers from the table in docs/footprint.md, for example
 * `{ binary: '3.3 MB', target: 'aarch64-apple-darwin', image: '6.3 MB', idle: '5.6 MiB' }`.
 * Returns null if the file or a row is missing, so the landing page shows no numbers.
 */
function readFootprint() {
  const file = path.join(docsDir, 'footprint.md');
  if (!fs.existsSync(file)) return null;
  const rows = fs
    .readFileSync(file, 'utf8')
    .split('\n')
    .filter((l) => l.startsWith('|'))
    .map((l) => l.split('|').slice(1, -1).map((c) => c.trim()));
  const row = (start) => rows.find((r) => r[0]?.startsWith(start));
  // "median 5.6 MiB (5 776 KiB, 5 runs)" -> "5.6 MiB"
  const value = (r) => r?.[1]?.replace(/^median\s+/, '').replace(/\s*\(.*$/, '').trim() || null;
  const binary = row('Release binary');
  const out = {
    binary: value(binary),
    target: binary?.[0].match(/`([^`]+)`/)?.[1] ?? null,
    image: value(row('Container image')),
    idle: value(row('Memory (RSS) at idle')),
  };
  return Object.values(out).every(Boolean) ? out : null;
}

/**
 * Writes the generated pages and media. Returns the pages, for example
 * `[{ source: 'docs/features.md', route: '/docs/features/', title: 'Features', headings: [...] }]`.
 */
export function syncDocs({ quiet = false } = {}) {
  for (const dir of Object.values(OUTPUT_DIRS)) fs.rmSync(dir, { recursive: true, force: true });
  const files = listDocs();
  const pages = new Set(files);
  const result = [];
  for (const relPath of files) {
    const text = fs.readFileSync(path.join(docsDir, relPath), 'utf8');
    const { title, body } = takeTitle(text, relPath);
    const content = rewriteLinks(body, relPath, pages);
    const description = takeDescription(content);
    const hidden = HIDDEN.includes(relPath.replace(/\.md$/, ''));
    const frontmatter = [
      '---',
      `title: ${JSON.stringify(title)}`,
      description ? `description: ${JSON.stringify(description)}` : null,
      `editUrl: ${JSON.stringify(`${GITHUB}/edit/main/docs/${relPath}`)}`,
      'sidebar:',
      `  order: ${sidebarOrder(relPath)}`,
      hidden ? '  hidden: true' : null,
      LABELS[relPath.replace(/\.md$/, '')] ? `  label: ${JSON.stringify(LABELS[relPath.replace(/\.md$/, '')])}` : null,
      '---',
      '',
      `<!-- Generated from docs/${relPath} by website/scripts/sync-docs.mjs. Do not edit. -->`,
    ];
    const out = outputOf(relPath);
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, `${frontmatter.filter((l) => l !== null).join('\n')}\n\n${content}`);
    result.push({ source: `docs/${relPath}`, route: routeOf(relPath), title, headings: headingsOf(body) });
  }
  const media = path.join(docsDir, 'media');
  if (isDirectory(media)) copyImages(media, OUTPUT_DIRS.media);
  // The landing page components read this file (they cannot read docs/ in the build).
  const alts = readmeAltTexts();
  const images = isDirectory(OUTPUT_DIRS.media) ? fs.readdirSync(OUTPUT_DIRS.media).sort() : [];
  // README order first, then the images that the README does not use, by name.
  const known = Object.keys(alts);
  const rank = (f) => (known.includes(f) ? known.indexOf(f) : known.length);
  const mediaList = images
    .sort((a, b) => rank(a) - rank(b) || a.localeCompare(b))
    .map((file) => ({ file, alt: alts[file] ?? null }));
  fs.mkdirSync(OUTPUT_DIRS.data, { recursive: true });
  fs.writeFileSync(
    path.join(OUTPUT_DIRS.data, 'site-data.json'),
    `${JSON.stringify({ pages: result, media: mediaList, footprint: readFootprint() }, null, 2)}\n`,
  );
  if (!quiet) console.log(`sync-docs: wrote ${result.length} pages from docs/`);
  return result;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  syncDocs();
}
