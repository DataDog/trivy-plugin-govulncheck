# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/)
# Copyright 2026-present Datadog, Inc.
#
# Trivy govulncheck plugin
# Use 'make deps' to download dependencies (go mod tidy).
# If you see TLS/certificate errors (e.g. in IDE sandbox), run go mod tidy from your terminal
# or in an environment that has access to your Go proxy / cert store.

.PHONY: deps build clean test test-integration license-report add-license check-license

deps:
	go mod tidy
	go mod download

VERSION ?= 0.1.1

build: deps
	go build -ldflags "-X main.pluginVersion=$(VERSION)" -o trivy-govulncheck .

clean:
	rm -f trivy-govulncheck

test: deps
	go test -v ./...

# Integration tests: need trivy on PATH (image extraction uses go-containerregistry; govulncheck is built into the plugin).
# Uses image tianon/gosu:latest (override with TRIVY_PLUGIN_GOVULNCHECK_IMAGE).
test-integration: build
	go test -v -tags=integration ./...

# Third-party license report (CSV) with Component, Origin, License, and Copyright.
# Uses dd-license-attribution so the Copyright column is populated.
#
# Install dd-license-attribution (pinned version):
#   pip install 'dd-license-attribution @ git+https://github.com/DataDog/dd-license-attribution.git@$(DDLA_VERSION)'
# On macOS, install system deps first so scancode-toolkit (pyicu) can build:
#   brew install icu4c pkg-config libmagic && brew link icu4c --force
# Then set PKG_CONFIG_PATH if needed: export PKG_CONFIG_PATH="$(brew --prefix icu4c)/lib/pkgconfig"
#
# Or from a clone: git clone --depth 1 --branch $(DDLA_VERSION) https://github.com/DataDog/dd-license-attribution && cd dd-license-attribution && pip install .
DDLA_VERSION ?= v0.5.0
DDLA_REPO_URL ?= https://github.com/DataDog/trivy-plugin-govulncheck
license-report: deps
	@which dd-license-attribution >/dev/null 2>&1 || (echo "Install dd-license-attribution $(DDLA_VERSION). On macOS first: brew install icu4c pkg-config libmagic && brew link icu4c --force. Then: pip install 'dd-license-attribution @ git+https://github.com/DataDog/dd-license-attribution.git@$(DDLA_VERSION)'" && exit 1)
	@dd-license-attribution generate-sbom-csv --no-pypi-strategy --no-npm-strategy --no-gh-auth "$(DDLA_REPO_URL)" > LICENSE-3rdparty.csv
	@echo "Wrote LICENSE-3rdparty.csv ($(shell wc -l < LICENSE-3rdparty.csv 2>/dev/null || echo 0) lines)"

# Add Apache 2.0 license header to source files. Requires addlicense: go install github.com/google/addlicense@latest
# Uses .addlicense-header template (// style for Go). Only processes *.go; for other files (e.g. .sh, Makefile) add headers manually or use a separate template.
ADDLICENSE_COPYRIGHT := Datadog, Inc.
ADDLICENSE_YEAR ?= 2026-present
add-license:
	@which addlicense >/dev/null 2>&1 || (echo "Install addlicense: go install github.com/google/addlicense@latest" && exit 1)
	addlicense -c "$(ADDLICENSE_COPYRIGHT)" -y "$(ADDLICENSE_YEAR)" -f .addlicense-header \
		-ignore 'vendor/**' -ignore 'dist/**' -ignore '.git/**' -ignore 'third_party_licenses/**' \
		-ignore '**/trivy-govulncheck' -ignore '**/*.yaml' -ignore '**/*.yml' -v .
	@echo "License headers added. Run 'make check-license' to verify."

# Verify that add-license and license-report would not change anything (for CI).
# Fails if any file is missing the license header or if LICENSE-3rdparty.csv is out of date.
check-license: deps
	@which addlicense >/dev/null 2>&1 || (echo "Install addlicense: go install github.com/google/addlicense@latest" && exit 1)
	@which dd-license-attribution >/dev/null 2>&1 || (echo "Install dd-license-attribution $(DDLA_VERSION). On macOS first: brew install icu4c pkg-config libmagic && brew link icu4c --force. Then: pip install 'dd-license-attribution @ git+https://github.com/DataDog/dd-license-attribution.git@$(DDLA_VERSION)'" && exit 1)
	@echo "Checking license headers..."
	@addlicense -check -c "$(ADDLICENSE_COPYRIGHT)" -y "$(ADDLICENSE_YEAR)" -f .addlicense-header \
		-ignore 'vendor/**' -ignore 'dist/**' -ignore '.git/**' -ignore 'third_party_licenses/**' \
		-ignore '**/trivy-govulncheck' -ignore '**/*.yaml' -ignore '**/*.yml' .
	@echo "Checking LICENSE-3rdparty.csv is up to date..."
	@tmp=$$(mktemp); \
	dd-license-attribution generate-sbom-csv --no-pypi-strategy --no-npm-strategy --no-gh-auth "$(DDLA_REPO_URL)" > $$tmp; \
	diff -u LICENSE-3rdparty.csv $$tmp > /dev/null || { echo "LICENSE-3rdparty.csv is out of date. Run 'make license-report' and commit."; diff -u LICENSE-3rdparty.csv $$tmp; rm -f $$tmp; exit 1; }; \
	rm -f $$tmp
	@echo "License check passed."
