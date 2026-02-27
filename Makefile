# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/)
# Copyright 2026-present Datadog, Inc.
#
# Trivy govulncheck plugin
# Use 'make deps' to download dependencies (go mod tidy).
# If you see TLS/certificate errors (e.g. in IDE sandbox), run go mod tidy from your terminal
# or in an environment that has access to your Go proxy / cert store.

.PHONY: deps build clean test test-integration license-report license-save add-license check-license

deps:
	go mod tidy
	go mod download

VERSION ?= 0.1.0

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

# Third-party license report (CSV). Requires go-licenses: go install github.com/google/go-licenses/v2@latest
# Ignore Go stdlib only so go-licenses can complete (tool treats stdlib "no module info" as fatal; we only need third-party licenses). Real third-party failures still propagate.
GO_LICENSES_IGNORE_STDLIB := --ignore=archive --ignore=bufio --ignore=bytes --ignore=cmp --ignore=compress --ignore=container --ignore=context --ignore=crypto --ignore=database --ignore=debug --ignore=encoding --ignore=errors --ignore=flag --ignore=fmt --ignore=go --ignore=hash --ignore=internal --ignore=io --ignore=iter --ignore=log --ignore=maps --ignore=math --ignore=mime --ignore=net --ignore=os --ignore=path --ignore=reflect --ignore=regexp --ignore=runtime --ignore=slices --ignore=sort --ignore=strconv --ignore=strings --ignore=sync --ignore=syscall --ignore=testing --ignore=text --ignore=time --ignore=unicode --ignore=unique --ignore=vendor --ignore=weak

# Output: LICENSE-3rdparty.csv with columns Component,Origin,License,Copyright.
# Copyright column is left empty; run 'make license-save' to collect full license/copyright files.
# Warnings and errors in go-licenses output may be expected (see https://github.com/google/go-licenses).
license-report: deps
	@which go-licenses >/dev/null 2>&1 || (echo "Install go-licenses: go install github.com/google/go-licenses/v2@latest" && exit 1)
	@echo "Component,Origin,License,Copyright" > LICENSE-3rdparty.csv
	@go-licenses report . $(GO_LICENSES_IGNORE_STDLIB) 2>/dev/null | awk -F',' 'BEGIN {OFS=","} {print $$1,$$2,$$3,""}' >> LICENSE-3rdparty.csv
	@echo "Wrote LICENSE-3rdparty.csv ($(shell wc -l < LICENSE-3rdparty.csv 2>/dev/null || echo 0) lines)"

# Save all third-party license and copyright files to third_party_licenses/ (for redistribution compliance).
# Warnings and errors in go-licenses output may be expected (see https://github.com/google/go-licenses).
license-save: deps
	@which go-licenses >/dev/null 2>&1 || (echo "Install go-licenses: go install github.com/google/go-licenses/v2@latest" && exit 1)
	@go-licenses save . $(GO_LICENSES_IGNORE_STDLIB) --save_path=third_party_licenses
	@echo "Saved licenses and notices to third_party_licenses/"

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
	@which go-licenses >/dev/null 2>&1 || (echo "Install go-licenses: go install github.com/google/go-licenses/v2@latest" && exit 1)
	@echo "Checking license headers..."
	@addlicense -check -c "$(ADDLICENSE_COPYRIGHT)" -y "$(ADDLICENSE_YEAR)" -f .addlicense-header \
		-ignore 'vendor/**' -ignore 'dist/**' -ignore '.git/**' -ignore 'third_party_licenses/**' \
		-ignore '**/trivy-govulncheck' -ignore '**/*.yaml' -ignore '**/*.yml' .
	@echo "Checking LICENSE-3rdparty.csv is up to date..."
	@tmp=$$(mktemp); \
	echo "Component,Origin,License,Copyright" > $$tmp; \
	go-licenses report . $(GO_LICENSES_IGNORE_STDLIB) 2>/dev/null | awk -F',' 'BEGIN {OFS=","} {print $$1,$$2,$$3,""}' >> $$tmp; \
	diff -u LICENSE-3rdparty.csv $$tmp > /dev/null || { echo "LICENSE-3rdparty.csv is out of date. Run 'make license-report' and commit."; diff -u LICENSE-3rdparty.csv $$tmp; rm -f $$tmp; exit 1; }; \
	rm -f $$tmp
	@echo "License check passed."
