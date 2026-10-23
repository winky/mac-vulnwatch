# REPO_DIR comes from this Makefile's own location, so `make -C <repo> install` works from
# anywhere.
REPO_DIR := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))

LABEL := io.github.winky.mac-vulnwatch
AGENTS_DIR := $(HOME)/Library/LaunchAgents
AGENT := $(AGENTS_DIR)/$(LABEL).plist
LOG_DIR := $(HOME)/Library/Logs/mac-vulnwatch
BIN_DIR ?= $(HOME)/.local/bin
DOMAIN := gui/$(shell id -u)

# When the daily scan runs, in local time.
HOUR ?= 9
MINUTE ?= 0

.DEFAULT_GOAL := help
.PHONY: install uninstall status run link unlink test lint help

install: ## Place the LaunchAgent that scans daily at HOUR:MINUTE (default 09:00), and load it
	@mkdir -p "$(AGENTS_DIR)" "$(LOG_DIR)"
	@sed -e 's|@REPO_DIR@|$(REPO_DIR)|g' -e 's|@LOG_DIR@|$(LOG_DIR)|g' -e 's|@HOME@|$(HOME)|g' \
	  -e 's|@HOUR@|$(HOUR)|g' -e 's|@MINUTE@|$(MINUTE)|g' \
	  "$(REPO_DIR)/launchd/$(LABEL).plist.in" > "$(AGENT).new"
	@if cmp -s "$(AGENT).new" "$(AGENT)"; then \
	  rm -f "$(AGENT).new"; \
	else \
	  mv "$(AGENT).new" "$(AGENT)"; \
	  echo "placed   $(AGENT)"; \
	  launchctl bootout "$(DOMAIN)/$(LABEL)" 2> /dev/null || true; \
	fi
	@if launchctl print "$(DOMAIN)/$(LABEL)" > /dev/null 2>&1; then \
	  echo "loaded   $(LABEL)"; \
	else \
	  launchctl bootstrap "$(DOMAIN)" "$(AGENT)" && echo "loaded   $(LABEL)"; \
	fi

uninstall: ## Unload the LaunchAgent and remove it (reports and config are kept)
	@launchctl bootout "$(DOMAIN)/$(LABEL)" 2> /dev/null || true
	@rm -f "$(AGENT)"
	@echo "removed  $(LABEL)"

status: ## Show whether the LaunchAgent is loaded, and when it last ran
	@if launchctl print "$(DOMAIN)/$(LABEL)" > /dev/null 2>&1; then \
	  echo "loaded   $(LABEL)"; \
	  launchctl print "$(DOMAIN)/$(LABEL)" | grep -E 'last exit code|runs =' | sed 's/^[[:space:]]*/         /'; \
	else \
	  echo "not loaded"; \
	fi

run: ## Start the LaunchAgent now, as launchd would (output goes to the log)
	@launchctl kickstart "$(DOMAIN)/$(LABEL)"
	@echo "started; follow it with: tail -f $(LOG_DIR)/mac-vulnwatch.log"

link: ## Link the mac-vulnwatch command into BIN_DIR (default ~/.local/bin)
	@mkdir -p "$(BIN_DIR)"
	@ln -sfn "$(REPO_DIR)/bin/mac-vulnwatch" "$(BIN_DIR)/mac-vulnwatch"
	@echo "linked   $(BIN_DIR)/mac-vulnwatch"

unlink: ## Remove the link made by `make link`
	@rm -f "$(BIN_DIR)/mac-vulnwatch"

test: ## Run the tests (bash and jq only)
	@/bin/bash "$(REPO_DIR)/tests/run.sh"

lint: ## Run shellcheck
	@shellcheck -x -P "$(REPO_DIR)" "$(REPO_DIR)/bin/mac-vulnwatch" "$(REPO_DIR)"/collectors/*.sh "$(REPO_DIR)"/lib/*.sh "$(REPO_DIR)"/tests/run.sh

help: ## Display available targets
	@echo "Usage: make [target] [HOUR=9 MINUTE=0]"
	@echo ""
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-10s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
