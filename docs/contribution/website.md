---
type: Guide
title: Website
description: How the landing page and the themed docs are built, checked, and deployed to Cloudflare.
status: draft
tags: [contribution, website, docs]
---

# Website

The public site is one static origin: the landing page at `/`, the How it works page at `/how-it-works`, the Use cases page at `/use-cases`, a page for people using an app built on Tendril at `/for-users`, and this docs bundle, rendered by okf-wiki, at `/docs/`. Everything lives in `site/`. The production domain is `tendril.agync.dev`.

## Layout

| Path | Purpose |
|---|---|
| `site/index.html`, `site/how-it-works.html`, `site/use-cases.html`, `site/for-users.html`, `site/404.html` | The landing, How it works, Use cases, app users and not-found pages. No inline scripts or styles; the build refuses them |
| `site/assets/` | CSS, JS, and self-hosted IBM Plex fonts (SIL OFL 1.1, `assets/fonts/OFL.txt`) |
| `site/brand/` | Brand sources: the mark, the outlined wordmark, the social card layout, and the avatar and touch icon SVGs |
| `site/assets/img/` | Rendered logos, avatars and social cards, served at `/assets/img/` |
| `site/tokens.json` | The one source of colour tokens, light and dark |
| `site/docs-theme/` | okf-wiki theme: template with a home link, head slot, fonts, mark, and `tokens.base.css` |
| `site/scripts/build.py` | Writes both token stylesheets, lays out the docs theme, and assembles `dist/` |
| `site/_headers` | Response headers, including a strict content security policy |
| `site/wrangler.jsonc` | Cloudflare Workers static assets, serving `site/dist` |
| `site/toolchain.sh`, `site/okf-wiki.sha256` | Pinned okf-wiki release for hosts without podman |

Colours are edited only in `tokens.json`. `build.py` writes the landing page's `tokens.css` and maps the same values onto the renderer's token names for the docs theme, so the two cannot drift.

## Build and check

```bash
make site          # render docs/ with the theme, then assemble site/dist
make site/serve    # serve site/dist on 127.0.0.1:4180 with _headers applied
make site/check    # in another terminal, while site/serve runs
```

`make site` renders with the pinned okf-wiki container image when podman is present, otherwise with the release that `toolchain.sh` downloads and verifies against `okf-wiki.sha256`.

`make site/check` runs in the pinned Playwright container image, which carries the browsers; `npm ci` installs the matching `playwright` and `@axe-core/playwright` from `site/package-lock.json`. It runs axe in both themes at 1440 and 390 px, including every scenario of the paths diagram, every pairing step and the How it works, Use cases and app users pages with their details open, and once more without script, fails on console errors, sideways scrolling and a header that does not fit at 360 px on any page with a nav, checks the skip link, the scenario tabs and the theme toggle from the keyboard, confirms the theme choice carries into the docs, and writes screenshots to `site/build/check/`. Findings in markup the renderer writes are reported as warnings.

## Brand

The mark is three parts in a row on a grid of 26 by 8 units: the host, a filled 8 unit square; the link, 10 by 2 units on the centre line; the joining device, an 8 unit square outlined 2 units thick. It is drawn in vine green, `#4A6B14` on light grounds and `#A9C76B` on dark ones, or in white on a green tile. The wordmark is lowercase `tendril` in IBM Plex Mono 600 with -3% tracking. In the lockup the mark sits on the baseline, 9 units from the wordmark set at 17, the same as the page header at one pixel to the unit. Corners stay square, and there are no gradients, glows or shadows.

`site/brand/mark.svg` is the one source of the mark and `site/brand/wordmark.svg` holds the wordmark as outlines, so no logo depends on a web font. `site/scripts/brand.mjs` builds every logo, icon and card from those two files, and the header's CSS mark uses the same proportions. To change the art, edit the sources or `site/brand/card.html`, then re-render:

```bash
make site/brand          # in the Playwright container; writes the SVGs and PNGs below
make -C site wordmark    # only when the font or tracking changes; needs fontTools and brotli
```

The render loads its pages from a stand-in origin served from `site/` and aborts every other request, so it fetches nothing from the network.

| File | Use |
|---|---|
| `site/assets/img/mark-on-light.svg`, `mark-on-dark.svg`, `mark-mono.svg` | The mark alone, transparent; the mono one takes `currentColor` |
| `site/assets/img/logo-on-light.svg`, `logo-on-dark.svg`, `logo-mono.svg` | The lockup, transparent, with the wordmark outlined; PNGs of the first two at 960 px wide |
| `site/assets/img/avatar.png`, `avatar-1024.png` | The default avatar, white mark on the green tile, 512 and 1024 px. Upload it as the GitHub organisation avatar and on social profiles |
| `site/assets/img/avatar-light*.png`, `avatar-dark*.png` | The mark on stone or on the dark ground, for places where the green tile does not fit |
| `site/favicon.svg`, `favicon-32.png`, `apple-touch-icon.png` | Browser and home screen icons; `brand.mjs` also writes the docs theme's copies |
| `site/assets/img/og.png`, `og-dark.png` | The Open Graph image, 1200 by 630, linked from every page |
| `site/assets/img/github-social.png`, `github-social-dark.png` | The repository social preview, 1280 by 640, with everything inside a central safe area. Upload `github-social.png` in the repository's Settings, under Social preview |

The light card and the green avatar are the defaults: the light card matches the site's default theme, and the green tile keeps its edge on both GitHub themes.

## Deploy

Cloudflare Workers Builds, connected to the repository in the dashboard:

| Setting | Value |
|---|---|
| Root directory | `site` |
| Build command | `make site` |
| Deploy command | `npx wrangler deploy` |
| Preview command | `npx wrangler preview` |

The Worker name in the dashboard must equal `name` in `wrangler.jsonc`. Setting up the connection and the custom domain is an owner step.

## Copy rules

Every behaviour the landing page describes must be true of the code. Check claims against `spec/` and the code before adding them, prefer plain words and short sentences, state the problem before the answer, and mark illustrative screens as such. Examples use a laptop and a phone, with the laptop as host, unless the point is machine to machine. Machine to machine enrollment uses a different pair: a Mac mini at home that runs the app is the host, and a server or a NAS, such as a backup box, is the joining machine. The Mac mini appears only there and on the Use cases page, and a server or a NAS appears nowhere else. Call the token an enrollment token and the host's record of spent tokens the burn log.

Say hybrid post-quantum, never quantum-safe or quantum-proof, and explain hybrid once in plain words: it stays secure as long as either the classic or the post-quantum algorithm holds. Name what it does not cover, relay mailbox proofs (Ed25519 only) and the iroh transport below the peer-to-peer path. On metadata, say that by default, on wire version 1, the mailbox key never changes and can link sessions, sizes are exact and keepalive and rekey timing is regular. Call Wire v2 opt-in wherever it appears, and say what it does in these terms: it changes the mailbox key every hour, rounds sizes up to fixed steps, varies keepalive and rekey timing and answers strangers who probe a host with a decoy, while addresses, when devices send and roughly how much stay visible, and a Wire v2 host still answers version 1 for older peers. Where the handshake is named, use its exact name, `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256`. The landing page lists it under "New, and ours", because the Noise code is Tendril's own and has had no outside review.

The code sample has one tab per language, each showing the same host flow with calls taken from that binding's tests. Each tab's install line uses the package name the binding declares (`tendril-sdk`, `@tendril-sdk/node`, `github.com/agync/tendril/bindings/go`, `tendril-runtime`, `tendril-cli`, `dev.agync:tendril-android`); those lines work once the packages are published. The browser SDK joins only as a client, through a Tendril relay or, with its opt-in p2p build, an iroh relay, so it has no host tab. The CLI tab has a second block, Enroll a server, with flags taken from `tendril-cli`, where the Mac mini (`./mac-mini-state`) enrolls a NAS (`./nas-state`). Its enrollment token travels in a file, never on the command line.

The paths diagram (`assets/js/net.js`) shows the six paths nearest first in five scenarios. It states only what the core does: every path is untrusted until the handshake proves the peer, peer-to-peer waits briefly so a nearer path can win, a relay sees addresses, timing, sizes and a mailbox key but not data, and a network change means a new handshake on another path with the same pairing. In the browser scenario the p2p path reads "via iroh relay", since a tab reaches it only through an iroh relay, with the opt-in p2p build. It makes no claim of automatic failover or a reconnection time. Its loop runs only on screen, stops on Pause, and shows each scenario's end state under reduced motion or without script.

The How it works page (`how-it-works.html`, `assets/css/how.css`, `assets/js/how.js`) explains the design in nine parts. Part 03 ends with machines that have no screen, as a sub block with a static figure, four steps and its own details panel, so the count stays at nine. Each part has a plain answer, a figure, what it means, and a native `<details>` panel with the exact mechanism, the numbers and a link to the design docs. Its claims follow the same rules, with `spec/` first, then the code, then `docs/`. Part 07 says who may use a relay: open by default, or admission by a list of mailbox keys, a shared secret or a signed ticket, which also hides whether a mailbox is online. Two limits apply to its wording: ranking and racing paths happens only in the Rust runtime (`dial_with_policy`), and reconnecting after a network change is the app's job, so the page states both in its details. Its figures are inline SVG or HTML styled by classes, and the illustrative ones say so. The pairing stepper and the contents rail need script, but without it every step and caption shows and each panel opens on its own. The relay figure's packets move only on screen and never under reduced motion.

The Use cases page (`use-cases.html`, `assets/css/uses.css`, with `how.css` and `how.js` reused) shows four cases in the How it works layout: a desktop app on a Mac mini reached from a phone, a laptop and a phone that sync with a browser tab joining through a relay, a NAS that needs no maker's cloud, and a server that enrolls CI runners. It ends with when to use something else. Each case opens with one short line of the person's moment, such as being out when the agent at home needs a yes, then states the problem and what changes, with one figure, what it means for the person using it and for the developer, and a details panel. Its device rules differ from the rest of the site: the Mac mini is the host that runs the desktop app, a NAS appears only in the appliance case, and a server only in the machine case. Its claims follow the same rules as How it works, and it states no measured timings or sizes. The landing page links to it from a short teaser after the six problems, and every page with a nav links to it in the header. On narrow screens the header drops Security first, then GitHub, and sets Use cases, How it works and Docs tighter below 375 px.

The app users page (`for-users.html`, `assets/css/users.css`, with `how.css` and `how.js` reused) is for people who use an app built on Tendril, not people building with it: someone who sees "secured by Tendril" in an app and asks why they should trust it with their data. It answers in five short parts, in one column with no contents rail: what it does for you, what you will see when you pair, what you control, what it cannot promise, and how to check. Its wording is for a reader who is not a developer. Protocol names, algorithms and API calls appear only inside The details panels. The limits part always names four things: relays and networks still see addresses, timing and sizes; the code is new with no outside review; post-quantum protection is hybrid and holds while either algorithm does; and the app itself still sees your data, because Tendril protects the link, not the app. It says what an app can show, such as the list of devices, never what an app will show, and it marks its screens as examples. It uses the laptop and phone pair. It has no header tab: the landing page links to it from one quiet line under the hero buttons, and every page's footer links to it.
