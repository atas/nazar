GO ?= go
SWIFT ?= swift
# Only directories that exist, so `make test` works while the tree grows.
SRC_DIRS := $(wildcard core cmd internal test bridge loaders)
PKGS := $(patsubst %,./%/...,$(filter-out test,$(SRC_DIRS)))
SWIFTPKG := --package-path macos --scratch-path build/swift -Xlinker -L$(CURDIR)/build
AGENT := build/nazar-agent.app
# The release version: the agent's CFBundleShortVersionString. The CLI is
# built with it, and the UI's Info.plist must say the same (release.sh).
VERSION := $(shell /usr/bin/plutil -extract CFBundleShortVersionString raw -o - macos/Resources/Agent/Info.plist 2>/dev/null)
# Quoted in every recipe: the bundle name has a space.
UI_APP := build/Nazar UI.app

.PHONY: test vet vet-cross integration fuzz build clean swift-build swift-test archives conformance agent ui check-launchd integration-swift integration-run check release-prepare release release-zips release-tap linux-image linux linux-run linux-tarballs

# Unit tests against the fake platform (no Mac hardware, no prompts), then
# the bundle check's own tests and the agent's sources (Milestone 6).
# -count=1 so a restored build cache (CI) or an earlier local run never
# reports a stale "(cached)" ok.
test: vet
	$(GO) test -race -count=1 $(PKGS)
	@if [ "$$(uname)" = Darwin ]; then scripts/check-agent_test.sh && scripts/check-ui_test.sh && scripts/release_test.sh; else echo "check-agent_test, check-ui_test, release_test: skipped (need macOS codesign)"; fi
	@if [ "$$(uname)" = Linux ]; then scripts/release-linux_test.sh && scripts/install_test.sh; fi

# check-agent.sh against forged bundles (tiny C programs, ad-hoc signed, in
# a temporary folder) and the tree's agent sources; never starts nazar-agent.
.PHONY: check-agent-test
check-agent-test:
	scripts/check-agent_test.sh

vet:
	$(GO) vet $(PKGS)
	@if [ -d test ]; then $(GO) vet -tags integration ./test/... ./cmd/nazar/; fi
	@if [ -d test ]; then $(GO) vet -tags 'integration swiftplatform' ./test/...; fi
	@out="$$(gofmt -l $(SRC_DIRS))"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

# Type-check and vet the files the host OS never builds: peer_darwin.go (LOCAL_PEERCRED, the
# kernel-verified peer UID) on Linux CI, peer_linux.go on a Mac. Pure Go, so no cgo needed;
# bridge/ is the core as a C archive (cgo only), so it is left out.
CROSS_PKGS := $(filter-out ./bridge/...,$(PKGS))
vet-cross:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) vet $(CROSS_PKGS)
	@if [ -d test ]; then CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) vet -tags integration ./test/...; fi
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) vet $(CROSS_PKGS)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) vet -tags 'linuxplatform linuxe2e' $(CROSS_PKGS)
	@if [ -d test ]; then CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) vet -tags 'linuxplatform linuxe2e' ./test/...; fi

# The Linux suite in a container (test/linux): a software TPM (swtpm), the
# container's own system bus with polkitd, OpenSSH, git and kubectl, run as
# the unprivileged user nazartest. The source is mounted read-only and
# copied inside; nothing in the container writes the host. `make linux` runs
# everything; `make linux-run CMD='go test ./core/...'` runs one command
# (the whole of CMD is one argument, run by bash in the container, so
# quotes, && and | in it work as they would at a prompt). seccomp and
# AppArmor are off in the container because the procfs tests need
# unprivileged user and mount namespaces (they fail in the image without
# them, they never skip).
LINUX_IMAGE ?= nazar-linux-test
LINUX_RUN := docker run --rm --init --security-opt seccomp=unconfined --security-opt apparmor=unconfined -v "$(CURDIR)":/src:ro
linux-image:
	docker build -t $(LINUX_IMAGE) test/linux
linux: linux-image
	$(LINUX_RUN) $(LINUX_IMAGE)
linux-run: export NAZAR_LINUX_CMD = $(CMD)
linux-run: linux-image
	@[ -n "$$NAZAR_LINUX_CMD" ] || { echo "linux-run: CMD='command' is required" >&2; exit 1; }
	$(LINUX_RUN) $(LINUX_IMAGE) "$$NAZAR_LINUX_CMD"

# Real /usr/bin/ssh, /usr/sbin/sshd, ssh-add, ssh-keygen and git against
# nazar-testd (fake platform, software key), plus the unified-log sender
# check. On macOS, and on Linux inside the test container
# (make linux-run CMD='make integration'; make linux runs it too). The
# unified-log check is macOS only. The fake platform has macOS traits on
# Linux too, so the container run covers real ssh, sshd and git on Linux,
# not Linux gating or wording: that is the Linux end-to-end test.
integration:
	$(GO) test -race -tags integration -count=1 ./test/integration/ ./cmd/nazar/

# The real core on the real Swift platform end to end: real ssh, sshd and
# git against NazarSmokeHost.
integration-swift: swift-build
	NAZAR_SMOKE_HOST=$(CURDIR)/build/swift/debug/NazarSmokeHost $(GO) test -race -tags 'integration swiftplatform' -count=1 -run '^TestSwiftPlatform' ./test/integration/

# The one verification command: everything automated, nothing that
# needs a person. check-launchd is separate (it registers a test agent).
check: test swift-test conformance integration integration-swift agent ui integration-run linux

# Opt-in: nazar install / uninstall against the real launchd under a random
# dev.nazar.test.* label and a temporary HOME.
check-launchd:
	$(GO) test -tags launchd -count=1 -run '^TestInstallWithRealLaunchd$$' -v ./cmd/nazar/

# Short fuzz runs of the parsers that read untrusted input.
#
# The budget is an execution count, not wall time, so that a failure here is a real
# finding. With a duration, Go 1.25-1.26 race the workers' shutdown against the deadline
# and fail a clean run with "context deadline exceeded" (golang/go#75804, fixed only in
# 1.27); and the coordinator credits a worker's executions only when its call returns,
# while minimising a new coverage-expanding input is quadratic in its size and allowed
# 60 s (-fuzzminimizetime) — longer than the whole run — so on a 2-CPU runner the log
# sits at "0/sec" for most of the budget. A count sets no deadline context, so it cannot
# race, and it ends when the work is done. ~200k executions is what 20 s achieved on a
# 2-CPU runner. Override for a longer local hunt: make fuzz FUZZTIME=10m
FUZZTIME ?= 200000x
fuzz:
	$(GO) test ./core/config -run '^$$' -fuzz '^FuzzParse$$' -fuzztime $(FUZZTIME)
	$(GO) test ./core/audit -run '^$$' -fuzz '^FuzzParseLine$$' -fuzztime $(FUZZTIME)
	$(GO) test ./core/ssh/agentproto -run '^$$' -fuzz '^FuzzParsePayload$$' -fuzztime $(FUZZTIME)
	$(GO) test ./core/ssh/agentproto -run '^$$' -fuzz '^FuzzParseSignRequest$$' -fuzztime $(FUZZTIME)

build:
	$(GO) build -o build/nazar ./cmd/nazar

# The Go core as C archives (spec 4.7): the app's, and the conformance
# host's. go build is incremental, so these always run.
archives:
	$(GO) build -buildmode=c-archive -o build/libnazar-core.a ./bridge
	$(GO) build -buildmode=c-archive -o build/libnazar-conformance.a ./bridge/conformancehost

swift-build: archives
	$(SWIFT) build $(SWIFTPKG)

# Swift unit tests: real Secure Enclave (no user presence), temporary
# keychains, test log subsystems; nothing that needs a person.
swift-test: archives
	$(SWIFT) test $(SWIFTPKG)

# core/platform/conformance against the real Swift platform, through the C ABI.
conformance: swift-build
	build/swift/debug/NazarConformanceHost real -test.v -test.count=1 -test.skip '^TestNazar(Run|K8s)'
	build/swift/debug/NazarConformanceHost seamed -test.v -test.count=1 -test.skip '^TestNazar(Run|K8s)'

# nazar run end to end on the Mac: the CLI and loaders of the
# bundle `make agent` built, real npx installing from a registry the test
# serves on 127.0.0.1, against the core in the conformance host on the
# Swift platform's real process seams; keys, gates and the vault are the
# Go fake's (seamed mode: no Secure Enclave needed). The k8s plugin on the
# same seams: the real kubectl runs build/nazartest/nazar, the
# nazartest build of the CLI (its k8s credential may dial
# NAZAR_TEST_CONTROL_SOCKET; never shipped), signed ad hoc as dev.nazar.cli
# so the test daemon can pin its cdhash. Then no Swift buffer may be left.
integration-run: agent swift-build
	$(GO) build -tags nazartest -o build/nazartest/nazar ./cmd/nazar
	codesign --force --sign - --options runtime --identifier dev.nazar.cli build/nazartest/nazar
	NAZAR_AGENT_APP=$(CURDIR)/$(AGENT) NAZAR_TEST_CLI=$(CURDIR)/build/nazartest/nazar build/swift/debug/NazarConformanceHost seamed -test.v -test.count=1 -test.run '^(TestNazarRun.*|TestNazarK8s.*|TestNoBoundaryLeaks)$$'

# nazar-agent.app (spec 4, 12; Milestone 6), ad-hoc signed (never a real
# identity in automation): the background service with the CLI inside it,
# and nazar run's loaders, sealed with the bundle.
# An ad-hoc agent has no team to trust the CLI by, so it pins the CLI it
# ships (secret values go to that CLI only): the CLI is built and
# signed first, and its cdhash is compiled into the Go core the agent
# links (-X main.devCLIPin), so the pin is in the agent's code, which the
# kernel holds to the agent's signature. A team-signed build ignores it.
# The executable is nazar-agent, never a name that differs from the CLI's
# `nazar` only by case (a case-insensitive volume, the APFS default, would
# make them one file). check-agent.sh checks the bundle without starting it.
agent: archives
	$(GO) build -ldflags "-X main.version=$(VERSION)" -o build/nazar ./cmd/nazar
	codesign --force --sign - --options runtime --identifier dev.nazar.cli build/nazar
	pin=$$(/usr/bin/codesign -dvvv build/nazar 2>&1 | sed -n 's/^CDHash=//p'); \
	  [ -n "$$pin" ] || { echo "agent: no cdhash for build/nazar" >&2; exit 1; }; \
	  $(GO) build -buildmode=c-archive -ldflags "-X main.devCLIPin=$$pin" -o build/libnazar-core.a ./bridge
	$(SWIFT) build -c release $(SWIFTPKG) --product NazarAgent
	rm -rf $(AGENT)
	mkdir -p $(AGENT)/Contents/MacOS $(AGENT)/Contents/Resources/loaders/node $(AGENT)/Contents/Resources/loaders/python
	cp macos/Resources/Agent/Info.plist $(AGENT)/Contents/Info.plist
	cp macos/Resources/AppIcon.icns $(AGENT)/Contents/Resources/AppIcon.icns
	cp loaders/node/env.cjs $(AGENT)/Contents/Resources/loaders/node/env.cjs
	cp loaders/python/sitecustomize.py $(AGENT)/Contents/Resources/loaders/python/sitecustomize.py
	cp build/swift/release/NazarAgent $(AGENT)/Contents/MacOS/nazar-agent
	cp build/nazar $(AGENT)/Contents/MacOS/nazar
	codesign --force --sign - --options runtime --identifier dev.nazar.cli $(AGENT)/Contents/MacOS/nazar
	codesign --force --sign - --options runtime $(AGENT)
	scripts/check-agent.sh $(AGENT)

# Nazar UI.app (spec 6.1, Milestone 6), ad-hoc signed: a separate, optional
# app with no CLI of its own. An ad-hoc build has no team to trust the CLI
# by, so it pins the one CLI build it runs: the cdhash of the agent's CLI
# just built, written into its Info.plist (NazarDevCLICDHash) before the
# bundle is signed, so the seal covers it. A team-signed build ignores the
# pin (CLIRequirement). check-ui.sh checks the bundle without starting it.
ui: agent
	$(SWIFT) build -c release $(SWIFTPKG) --product NazarUIApp
	rm -rf "$(UI_APP)"
	mkdir -p "$(UI_APP)/Contents/MacOS" "$(UI_APP)/Contents/Resources"
	cp macos/Resources/UI/Info.plist "$(UI_APP)/Contents/Info.plist"
	cp macos/Resources/AppIcon.icns "$(UI_APP)/Contents/Resources/AppIcon.icns"
	cp build/swift/release/NazarUIApp "$(UI_APP)/Contents/MacOS/NazarUI"
	pin=$$(/usr/bin/codesign -dvvv $(AGENT)/Contents/MacOS/nazar 2>&1 | sed -n 's/^CDHash=//p'); \
	  [ -n "$$pin" ] && /usr/bin/plutil -insert NazarDevCLICDHash -string "$$pin" "$(UI_APP)/Contents/Info.plist"
	codesign --force --sign - --options runtime "$(UI_APP)"
	scripts/check-ui.sh "$(UI_APP)" $(AGENT)

# The release (spec 12; docs/RELEASING.md): two zipped bundles for two
# casks. release-prepare copies the ad-hoc bundles to build/release for
# signing (the UI's development pin removed). `make release`, run by a
# person with the Developer ID certificate, then signs them inside out
# (the CLI first, so the agent's seal covers it), notarizes and staples
# them, verifies them, zips them, renders the casks and prints the
# sha256s (scripts/release-sign.sh):
#   NAZAR_SIGN_ID='Developer ID Application: NAME (TEAMID)' NAZAR_NOTARY_PROFILE=nazar-notary make release
#   NAZAR_SIGN_ID=- DRY_RUN=1 make release     # the path end to end, ad hoc, no notary
# CI and the tests never give it a real identity. release-zips refuses
# anything not signed that way, then zips both and renders the casks;
# release-tap renders the casks into a tap checkout (TAP=path) from the
# signed zips, without committing anything.
RELEASE := build/release
release-prepare: agent ui
	scripts/release.sh prepare $(VERSION) $(AGENT) "$(UI_APP)" $(RELEASE)

# release-sign.sh without a folder only checks the variables (and, for a
# release, the tag), so a missing identity is refused before the build.
RELEASE_ENV = NAZAR_SIGN_ID="$(NAZAR_SIGN_ID)" NAZAR_NOTARY_PROFILE="$(NAZAR_NOTARY_PROFILE)" DRY_RUN="$(DRY_RUN)"
release:
	$(RELEASE_ENV) scripts/release-sign.sh $(VERSION)
	$(MAKE) release-prepare
	$(RELEASE_ENV) scripts/release-sign.sh $(VERSION) $(RELEASE)

release-zips:
	scripts/release.sh zips $(VERSION) $(RELEASE)

release-tap:
	@[ -d "$(TAP)/Casks" ] || { echo "release-tap: TAP=path to a tap checkout with Casks/" >&2; exit 1; }
	scripts/release.sh check-signed $(RELEASE)/nazar-agent.app dev.nazar.agent
	scripts/release.sh check-signed $(RELEASE)/nazar-agent.app/Contents/MacOS/nazar dev.nazar.cli
	scripts/release.sh check-signed "$(RELEASE)/Nazar UI.app" dev.nazar.ui
	scripts/release.sh casks $(VERSION) $(RELEASE)/nazar-$(VERSION).zip $(RELEASE)/nazar-ui-$(VERSION).zip "$(TAP)"
	@echo "release-tap: nothing committed; review with git -C \"$(TAP)\" diff, then commit and push the tap"

# The Linux half of a release (docs/RELEASING.md): the two tarballs, install.sh
# and SHA256SUMS in build/release-linux. Needs Linux; on a Mac, a build to look
# at is make linux-run CMD='make linux-tarballs VERSION=X.Y.Z' (in the
# container's copy of the tree). release.yml runs the script itself.
linux-tarballs:
	@[ -n "$(VERSION)" ] || { echo "linux-tarballs: VERSION=X.Y.Z is required" >&2; exit 1; }
	scripts/release-linux.sh tarballs "$(VERSION)" build/release-linux

clean:
	rm -rf build
