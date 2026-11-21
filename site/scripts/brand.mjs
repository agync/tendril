// Builds the brand assets from the two sources in site/brand/ and renders the PNGs with headless
// Chromium. Run it from site/ in the pinned Playwright image with `make brand`:
//
//   brand/mark.svg      the mark, on a 26 x 8 unit grid
//   brand/wordmark.svg  "tendril" outlined from IBM Plex Mono 600 by scripts/wordmark.py
//   brand/card.html     the social card layout
//
// Every logo, icon and card places that one mark path, so the geometry cannot drift. Pages load
// from a stand-in origin served from site/; any other request is aborted, so nothing is fetched
// from the network.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const site = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const at = (p) => path.join(site, p);
const { chromium } = await import(path.join(site, "node_modules/playwright/index.mjs"));

const COLOURS = {
  light: { bg: "#FAFAF9", ink: "#1C1917", accent: "#4A6B14" },
  dark: { bg: "#111114", ink: "#F4F4F5", accent: "#A9C76B" },
  onAccent: "#FFFFFF",
};

// The sources.
const attr = (svg, name) => svg.match(new RegExp(`\\s${name}="([^"]*)"`))[1];
const markSvg = readFileSync(at("brand/mark.svg"), "utf8");
const MARK = { d: attr(markSvg.slice(markSvg.indexOf("<path")), "d"), w: 26, h: 8 };
const wordSvg = readFileSync(at("brand/wordmark.svg"), "utf8");
const [inkLeft, inkTop, inkRight, inkBottom] = attr(wordSvg, "data-ink").split(" ").map(Number);
const WORD = { d: attr(wordSvg.slice(wordSvg.indexOf("<path")), "d"), upm: Number(attr(wordSvg, "data-upm")) };

const num = (v) => String(Math.round(v * 1000) / 1000);

// The mark with its top left corner at (x, y), u pixels to the grid unit.
function mark(x, y, u, fill, cls) {
  const paint = fill ? ` fill="${fill}"` : "";
  const klass = cls ? ` class="${cls}"` : "";
  return `<path${klass}${paint} fill-rule="evenodd" transform="translate(${num(x)} ${num(y)}) scale(${num(u)})" d="${MARK.d}"/>`;
}

// The lockup, in the landing header's own units: the mark 8 tall sits on the baseline, 9 to the
// left of the wordmark set at 17. The box is the ink: the mark's left edge to the l, the top of
// the d and l to the baseline overshoot.
const LOCKUP = (() => {
  const size = 17;
  const s = size / WORD.upm;
  const gap = 9;
  const top = inkTop * s;
  const bottom = inkBottom * s;
  const width = MARK.w + gap + (inkRight - inkLeft) * s;
  return { s, gap, top, bottom, width, height: bottom - top };
})();

function lockup(markFill, wordFill, classes) {
  const { s, gap, top, width, height } = LOCKUP;
  const wx = MARK.w + gap - inkLeft * s;
  const [mc, wc] = classes ?? [];
  const paint = (fill, cls) => (cls ? ` class="${cls}"` : "") + (fill ? ` fill="${fill}"` : "");
  return {
    viewBox: `0 ${num(top)} ${num(width)} ${num(height)}`,
    width,
    height,
    body:
      mark(0, -MARK.h, 1, markFill, mc) +
      `<path${paint(wordFill, wc)} transform="translate(${num(wx)} 0) scale(${num(s)})" d="${WORD.d}"/>`,
  };
}

const svg = (viewBox, body, w, h, label) =>
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${viewBox}" width="${num(w)}" height="${num(h)}"` +
  ` role="img" aria-label="${label}">${body}</svg>\n`;

// A square tile of side 1024 units with the mark centred, u units to the grid unit.
const tile = (side, u, bg, fg) =>
  svg(
    `0 0 ${side} ${side}`,
    `<rect width="${side}" height="${side}" fill="${bg}"/>` +
      mark((side - MARK.w * u) / 2, (side - MARK.h * u) / 2, u, fg),
    side,
    side,
    "Tendril",
  );

const files = {};

// Logos, transparent. "on-light" is drawn for light backgrounds, "on-dark" for dark ones.
const L = COLOURS.light;
const D = COLOURS.dark;
const markOnly = (fill) => svg(`0 0 ${MARK.w} ${MARK.h}`, mark(0, 0, 1, fill), MARK.w * 4, MARK.h * 4, "Tendril");
files["assets/img/mark-on-light.svg"] = markOnly(L.accent);
files["assets/img/mark-on-dark.svg"] = markOnly(D.accent);
files["assets/img/mark-mono.svg"] = markOnly("currentColor");
for (const [name, m, w] of [
  ["logo-on-light", L.accent, L.ink],
  ["logo-on-dark", D.accent, D.ink],
  ["logo-mono", "currentColor", "currentColor"],
]) {
  const l = lockup(m, w);
  files[`assets/img/${name}.svg`] = svg(l.viewBox, l.body, l.width * 4, l.height * 4, "Tendril");
}

// Avatars and icons. The mark spans 71% of the avatar, inside GitHub's circular crop, and sits
// on whole pixels in the 32 px favicon and the 180 px touch icon.
files["brand/avatar-green.svg"] = tile(1024, 28, L.accent, COLOURS.onAccent);
files["brand/avatar-light.svg"] = tile(1024, 28, L.bg, L.accent);
files["brand/avatar-dark.svg"] = tile(1024, 28, D.bg, D.accent);
const favicon = tile(256, 8, L.accent, COLOURS.onAccent);
files["favicon.svg"] = favicon;
files["docs-theme/assets/favicon.svg"] = favicon;
files["docs-theme/assets/brand-mark.svg"] = favicon;
files["brand/touch-icon.svg"] = tile(180, 4, L.accent, COLOURS.onAccent);

for (const [file, text] of Object.entries(files)) {
  mkdirSync(path.dirname(at(file)), { recursive: true });
  writeFileSync(at(file), text);
  console.log(`brand.mjs: ${file}`);
}

// The renders.
const icons = [
  { src: "brand/avatar-green.svg", out: "assets/img/avatar.png", size: 512 },
  { src: "brand/avatar-green.svg", out: "assets/img/avatar-1024.png", size: 1024 },
  { src: "brand/avatar-light.svg", out: "assets/img/avatar-light.png", size: 512 },
  { src: "brand/avatar-light.svg", out: "assets/img/avatar-light-1024.png", size: 1024 },
  { src: "brand/avatar-dark.svg", out: "assets/img/avatar-dark.png", size: 512 },
  { src: "brand/avatar-dark.svg", out: "assets/img/avatar-dark-1024.png", size: 1024 },
  { src: "favicon.svg", out: "favicon-32.png", size: 32 },
  { src: "brand/touch-icon.svg", out: "apple-touch-icon.png", size: 180 },
];
const logos = [
  { src: "assets/img/logo-on-light.svg", out: "assets/img/logo-on-light.png", width: 960 },
  { src: "assets/img/logo-on-dark.svg", out: "assets/img/logo-on-dark.png", width: 960 },
];
const cards = [
  { out: "assets/img/og.png", theme: "light", width: 1200, height: 630, padX: 80 },
  { out: "assets/img/og-dark.png", theme: "dark", width: 1200, height: 630, padX: 80 },
  { out: "assets/img/github-social.png", theme: "light", width: 1280, height: 640, padX: 140 },
  { out: "assets/img/github-social-dark.png", theme: "dark", width: 1280, height: 640, padX: 140 },
];

const ORIGIN = "https://brand.invalid";
const TYPES = { ".html": "text/html", ".woff2": "font/woff2", ".svg": "image/svg+xml" };
const pages = new Map();

const browser = await chromium.launch();
try {
  const context = await browser.newContext();
  await context.route("**/*", (route) => {
    const url = new URL(route.request().url());
    if (url.origin !== ORIGIN) return route.abort();
    const body = pages.get(url.pathname) ?? readFileSync(at(url.pathname.slice(1)));
    return route.fulfill({ body, contentType: TYPES[path.extname(url.pathname)] });
  });

  const shoot = async (html, width, height, out, transparent) => {
    const name = `/render/${path.basename(out, ".png")}.html`;
    pages.set(name, html);
    const page = await context.newPage();
    await page.setViewportSize({ width, height });
    await page.goto(ORIGIN + name, { waitUntil: "load" });
    await page.evaluate(() => document.fonts.ready);
    await page.screenshot({ path: at(out), omitBackground: transparent });
    await page.close();
    console.log(`brand.mjs: ${out} (${width} x ${height})`);
  };
  const frame = (svgText, width, height) =>
    `<!doctype html><style>html,body{margin:0;background:transparent}svg{display:block}</style>` +
    svgText.replace(/ width="[^"]*" height="[^"]*"/, ` width="${width}" height="${height}"`);

  for (const icon of icons) {
    await shoot(frame(files[icon.src], icon.size, icon.size), icon.size, icon.size, icon.out, false);
  }
  for (const logo of logos) {
    const height = Math.round((logo.width * LOCKUP.height) / LOCKUP.width);
    await shoot(frame(files[logo.src], logo.width, height), logo.width, height, logo.out, true);
  }
  const template = readFileSync(at("brand/card.html"), "utf8");
  for (const card of cards) {
    const l = lockup(null, null, ["m", "w"]);
    const html = template
      .replaceAll("{{THEME}}", card.theme)
      .replaceAll("{{PAD_X}}", String(card.padX))
      .replaceAll(
        "{{LOCKUP}}",
        `<svg class="lockup" viewBox="${l.viewBox}" role="img" aria-label="Tendril">${l.body}</svg>`,
      );
    await shoot(html, card.width, card.height, card.out, false);
  }
} finally {
  await browser.close();
}
