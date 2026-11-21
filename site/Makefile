.DEFAULT_GOAL := help

.PHONY: help site docs serve check brand wordmark clean

# The public origin, used for the canonical and Open Graph links.
SITE_URL ?= https://tendril.agync.dev

# The docs renderer. With podman, the pinned image (okf-wiki v1.2.0) renders. Without it, the
# binary from toolchain.sh renders, and the Makefile builds that toolchain if it is missing, which
# is the case on a Cloudflare build image. OKF_WIKI names another okf-wiki binary instead, with
# OKF_WIKI_VENDOR pointing at its built Mermaid bundle.
OKF_WIKI_IMAGE ?= ghcr.io/abn/okf-wiki@sha256:c6a3844ad2f6f1c453146d145ea1893c8d038b2d8dc6647ef328866bcb123264
OKF_WIKI ?=
OKF_WIKI_VENDOR ?=
TOOLCHAIN := .toolchain
PODMAN ?= podman

PORT ?= 4180

# The checks run in the pinned Playwright image, which carries the browsers; npm ci installs the
# matching playwright and axe packages from package-lock.json into node_modules/.
PLAYWRIGHT_IMAGE ?= mcr.microsoft.com/playwright:v1.65.0-noble@sha256:f6fe3cf9a493670b9a20f33597a807262abb25c40c31839ba4ac1dbc51fe7366
BUILD := build
DIST := dist

RENDER_FLAGS = --base /docs/ --brand tendril --brand-sub docs --title "Tendril docs" \
	--sections "usage:Using Tendril,architecture:Architecture,design:Design,reference:Reference,adr:Decisions,contribution:Contribution"

ifeq ($(strip $(OKF_WIKI)),)
ifeq ($(shell command -v $(PODMAN) 2>/dev/null),)
OKF_WIKI := $(TOOLCHAIN)/bin/okf-wiki
OKF_WIKI_VENDOR := $(TOOLCHAIN)/mermaid
NEED_TOOLCHAIN := 1
endif
endif

ifeq ($(strip $(OKF_WIKI)),)
RENDER = $(PODMAN) run --rm --network=none --user 0:0 --security-opt label=disable \
	-v "$(abspath ../docs):/content:ro" -v "$(abspath $(BUILD)/theme):/theme:ro" \
	-v "$(abspath $(BUILD)/render):/out" \
	$(OKF_WIKI_IMAGE) render --content /content --out /out --theme /theme $(RENDER_FLAGS)
else
RENDER = $(OKF_WIKI) render --content ../docs --out $(BUILD)/render --theme $(BUILD)/theme \
	$(if $(OKF_WIKI_VENDOR),--vendor $(OKF_WIKI_VENDOR)) $(RENDER_FLAGS)
endif

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-8s\033[0m %s\n", $$1, $$2}'

site: docs ## Build the landing page and the docs into dist/ (the deploy directory)
	python3 -I scripts/build.py assemble --site-url "$(SITE_URL)" --render $(BUILD)/render . $(DIST)

docs: ## Render ../docs with the Tendril theme into build/render
	$(if $(NEED_TOOLCHAIN),@test -x $(OKF_WIKI) || ./toolchain.sh)
	rm -rf $(BUILD)
	mkdir -p $(BUILD)/render
	python3 -I scripts/build.py theme docs-theme assets/fonts tokens.json $(BUILD)/theme
	$(RENDER)

serve: ## Serve dist/ on 127.0.0.1:$(PORT) with the _headers applied
	python3 -I scripts/serve.py $(DIST) $(PORT)

check: ## Run axe, console and keyboard checks on the served site in the Playwright container (needs make serve)
	$(PODMAN) run --rm --network=host --security-opt label=disable -v "$(CURDIR):/site" -w /site \
		$(PLAYWRIGHT_IMAGE) sh -c 'npm ci --no-audit --no-fund --loglevel=error && node scripts/check.mjs http://127.0.0.1:$(PORT)'

brand: ## Build the logos and icons from brand/ and render the PNGs in the Playwright container
	$(PODMAN) run --rm --security-opt label=disable -v "$(CURDIR):/site" -w /site \
		$(PLAYWRIGHT_IMAGE) sh -c 'npm ci --no-audit --no-fund --loglevel=error && node scripts/brand.mjs'

wordmark: ## Outline the wordmark into brand/wordmark.svg (needs fontTools and brotli on the host)
	python3 scripts/wordmark.py assets/fonts/ibm-plex-mono-latin-600-normal.woff2 brand/wordmark.svg

clean: ## Remove build output
	rm -rf $(BUILD) $(DIST)
