// Checks the served site: axe on the landing page, the How it works page, the Use cases page, the
// page for app users, the not-found page and a few docs pages in both themes (and every scenario of
// the paths diagram, every pairing step, the How it works, Use cases and app users pages with their
// details open, and How it works without script), no console errors, no sideways scrolling at 360 px, a header that fits at 360 px
// on every page with a nav, the scenario tabs and the theme toggle work from the keyboard and the
// theme choice carries into the docs, and full-page screenshots at 1440 and 390 px.
//
//   make serve                                  # in another terminal
//   make check                                  # runs this in the pinned Playwright container
//
// NODE_MODULES names a node_modules directory with playwright and @axe-core/playwright installed
// (default site/node_modules). SHOTS_DIR chooses where the screenshots go (default site/build/check).
// CHROME_PATH names a Chromium binary instead of the one Playwright downloads.

import { existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const site = path.resolve(here, "..");
const modules = process.env.NODE_MODULES ?? path.join(site, "node_modules");
if (!existsSync(path.join(modules, "playwright"))) {
  console.error(`check.mjs: no playwright under ${modules}; set NODE_MODULES`);
  process.exit(2);
}
const { chromium } = await import(path.join(modules, "playwright/index.mjs"));
const { default: AxeBuilder } = await import(
  path.join(modules, "@axe-core/playwright/dist/index.mjs")
);

const origin = process.argv[2] ?? "http://127.0.0.1:4180";
const shots = process.env.SHOTS_DIR ?? path.join(site, "build/check");
mkdirSync(shots, { recursive: true });

const pages = [
  { name: "landing", path: "/", shoot: true },
  { name: "how-it-works", path: "/how-it-works", shoot: true },
  { name: "use-cases", path: "/use-cases", shoot: true },
  { name: "for-users", path: "/for-users", shoot: true },
  { name: "docs-home", path: "/docs/", shoot: true },
  { name: "docs-overview", path: "/docs/overview.html", shoot: false },
  { name: "docs-cli-demo", path: "/docs/usage/cli-demo.html", shoot: false },
  { name: "not-found", path: "/no-such-page", shoot: false },
];
const sizes = [
  { name: "1440", width: 1440, height: 900 },
  { name: "390", width: 390, height: 844 },
];

// Findings in markup the okf-wiki renderer writes itself. The theme cannot change them, so they
// are reported, not failed; they belong to the renderer.
const RENDERER = new Set(["nested-interactive", "scrollable-region-focusable", "label-content-name-mismatch"]);
const warnings = [];
const failures = [];
const warn = (msg) => (warnings.push(msg), console.log(`WARN ${msg}`));
const fail = (msg) => (failures.push(msg), console.log(`FAIL ${msg}`));
const sideways = (page) =>
  page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);

const browser = await chromium.launch(
  process.env.CHROME_PATH ? { executablePath: process.env.CHROME_PATH } : {},
);
try {
  for (const theme of ["light", "dark"]) {
    for (const size of sizes) {
      const context = await browser.newContext({
        viewport: { width: size.width, height: size.height },
        deviceScaleFactor: size.width < 600 ? 2 : 1,
        colorScheme: theme,
        reducedMotion: "reduce",
      });
      for (const p of pages) {
        const page = await context.newPage();
        const problems = [];
        page.on("console", (m) => {
          if (m.type() === "error") problems.push(`console: ${m.text().slice(0, 200)}`);
        });
        page.on("pageerror", (e) => problems.push(`pageerror: ${e.message.slice(0, 200)}`));
        const response = await page.goto(origin + p.path, { waitUntil: "networkidle" });
        const expected = p.name === "not-found" ? 404 : 200;
        if (response.status() !== expected) fail(`${p.name}: status ${response.status()}`);
        await page.evaluate(() => document.fonts.ready);
        await page.waitForTimeout(300);

        const axe = await new AxeBuilder({ page })
          .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"])
          .analyze();
        for (const v of axe.violations) {
          const line = `${p.name} ${theme} ${size.name}: axe ${v.id} (${v.nodes.length}) ${v.help}`;
          if (p.path.startsWith("/docs/") && RENDERER.has(v.id)) warn(line);
          else fail(line);
        }
        // The paths diagram: each scenario's end state must pass axe too.
        if (p.name === "landing") {
          const tabs = page.locator('[data-net] [role="tab"]');
          for (let i = 1; i < (await tabs.count()); i++) {
            await tabs.nth(i).click();
            const scene = await new AxeBuilder({ page }).include("#paths")
              .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"]).analyze();
            for (const v of scene.violations) fail(`paths scenario ${i + 1} ${theme} ${size.name}: axe ${v.id} ${v.help}`);
          }
          await tabs.nth(0).click();
        }
        // How it works: every pairing step. Then, there, on Use cases and on the app users page,
        // every details panel open.
        const tags = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"];
        if (p.name === "how-it-works") {
          const next = page.locator("[data-seq-next]");
          for (let i = 1; i < 6; i++) {
            await next.click();
            const step = await new AxeBuilder({ page }).include("#pairing").withTags(tags).analyze();
            for (const v of step.violations) fail(`pairing step ${i + 1} ${theme} ${size.name}: axe ${v.id} ${v.help}`);
          }
        }
        if (["how-it-works", "use-cases", "for-users"].includes(p.name)) {
          await page.evaluate(() => document.querySelectorAll("details.more").forEach((d) => (d.open = true)));
          const open = await page.evaluate(() => [...document.querySelectorAll("details.more")].every((d) => d.open));
          if (!open) fail(`${p.name} ${theme} ${size.name}: a details panel did not open`);
          const opened = await new AxeBuilder({ page }).withTags(tags).analyze();
          for (const v of opened.violations) fail(`${p.name} details open ${theme} ${size.name}: axe ${v.id} (${v.nodes.length}) ${v.help}`);
          const wideOpen = await sideways(page);
          if (wideOpen > 0) fail(`${p.name} details open ${theme} ${size.name}: scrolls sideways by ${wideOpen}px`);
          await page.evaluate(() => document.querySelectorAll("details.more").forEach((d) => (d.open = false)));
        }
        const wide = await sideways(page);
        if (wide > 0) fail(`${p.name} ${theme} ${size.name}: scrolls sideways by ${wide}px`);
        for (const problem of problems.filter((x) => !x.includes("404 (Not Found)"))) {
          fail(`${p.name} ${theme} ${size.name}: ${problem}`);
        }
        if (p.shoot) {
          const file = path.join(shots, `${p.name}-${size.name}-${theme}.png`);
          await page.screenshot({ path: file, fullPage: true });
          console.log(`shot ${file}`);
        }
        console.log(`ok ${p.name} ${theme} ${size.name}: axe ${axe.violations.length}, passes ${axe.passes.length}`);
        await page.close();
      }
      await context.close();
    }
  }

  // Narrowest supported width, the skip link, and the theme toggle from the keyboard.
  const context = await browser.newContext({ viewport: { width: 360, height: 740 }, colorScheme: "light" });
  const page = await context.newPage();
  await page.goto(`${origin}/`, { waitUntil: "networkidle" });
  const wide = await sideways(page);
  if (wide > 0) fail(`landing 360: scrolls sideways by ${wide}px`);
  else console.log("ok landing 360: no sideways scroll");
  // The header fits on every page with a nav: nothing past the right edge, and the visible nav
  // links start after the wordmark ends and end before the theme toggle starts.
  for (const where of ["/", "/how-it-works", "/use-cases", "/for-users"]) {
    const narrow = await context.newPage();
    await narrow.goto(`${origin}${where}`, { waitUntil: "networkidle" });
    await narrow.evaluate(() => document.fonts.ready);
    const narrowWide = await sideways(narrow);
    const navFits = await narrow.evaluate(() => {
      const row = document.querySelector(".top-row").getBoundingClientRect();
      const inRow = [...document.querySelectorAll(".top-row > *")].every((el) => el.getBoundingClientRect().right <= row.right + 0.5);
      const links = [...document.querySelectorAll(".top-nav a")].filter((a) => a.offsetParent).map((a) => a.getBoundingClientRect());
      const brand = document.querySelector(".brand").getBoundingClientRect().right;
      const toggle = document.querySelector(".theme-toggle").getBoundingClientRect().left;
      return inRow && links.length > 0 && links[0].left >= brand + 4 && links[links.length - 1].right <= toggle - 4;
    });
    if (narrowWide > 0) fail(`${where} 360: scrolls sideways by ${narrowWide}px`);
    else if (!navFits) fail(`${where} 360: the header does not fit`);
    else console.log(`ok ${where} 360: no sideways scroll, the header fits`);
    await narrow.close();
  }
  await page.keyboard.press("Tab");
  const skip = await page.evaluate(() => document.activeElement?.textContent?.trim());
  if (skip !== "Skip to content") fail(`first Tab lands on ${JSON.stringify(skip)}`);
  let reached = false;
  for (let i = 0; i < 12 && !reached; i++) {
    await page.keyboard.press("Tab");
    reached = await page.evaluate(() => document.activeElement?.hasAttribute("data-theme-toggle"));
  }
  if (!reached) fail("the theme toggle is not reachable with Tab");
  await page.keyboard.press("Enter");
  // The paths diagram's scenario tabs move with the arrow keys, and motion has a Pause control.
  await page.locator('[data-net] [role="tab"]').first().focus();
  await page.keyboard.press("ArrowRight");
  await page.keyboard.press("ArrowRight");
  const picked = await page.evaluate(() => [document.activeElement?.id, document.activeElement?.getAttribute("aria-selected")]);
  if (picked[0] !== "nt-nat" || picked[1] !== "true") fail(`arrow keys on the scenario tabs reached ${JSON.stringify(picked)}`);
  else console.log("ok keyboard: the scenario tabs move with the arrow keys");
  if (!(await page.locator("[data-net-play]").isVisible())) fail("the paths diagram has no visible Pause control");
  const chosen = await page.evaluate(() => document.documentElement.dataset.theme);
  if (chosen !== "dark") fail(`the theme toggle chose ${JSON.stringify(chosen)}, not dark`);
  await page.goto(`${origin}/docs/`, { waitUntil: "networkidle" });
  const docsTheme = await page.evaluate(() => document.documentElement.dataset.theme);
  if (docsTheme !== "dark") fail(`the docs did not keep the dark choice (${docsTheme})`);
  else console.log("ok keyboard: the theme toggle works and the choice carries into the docs");
  await context.close();

  // Without script the How it works page reads in full: every step and caption shows, the
  // controls that need script stay hidden, and the page is no wider than the screen. Axe and
  // page.evaluate need script, so this pass measures with locators only.
  const plain = await browser.newContext({ viewport: { width: 390, height: 844 }, javaScriptEnabled: false });
  const bare = await plain.newPage();
  await bare.goto(`${origin}/how-it-works`, { waitUntil: "load" });
  const steps = await bare.locator(".seq-list li:visible").count();
  const machineSteps = await bare.locator(".m2m-list li:visible").count();
  if (machineSteps !== 4) fail(`how-it-works without script shows ${machineSteps} of 4 enrollment steps`);
  const hiddenCtl = !(await bare.locator(".seq-ctl").isVisible());
  const bodyBox = await bare.locator("body").boundingBox();
  if (steps !== 6) fail(`how-it-works without script shows ${steps} of 6 pairing steps`);
  else if (!hiddenCtl) fail("how-it-works without script shows controls that need script");
  else if (bodyBox.width > 390) fail(`how-it-works without script is ${bodyBox.width}px wide`);
  else console.log("ok how-it-works without script: all six steps, no script-only controls");
  await plain.close();
} finally {
  await browser.close();
}

console.log(`warnings (renderer): ${warnings.length}`);
console.log(failures.length ? `FAILED: ${failures.length}` : "PASSED");
process.exit(failures.length ? 1 : 0);
