PREFIX ?= $(HOME)/.local
BINARY := touchid-ssh-agent

.PHONY: build test test-docker test-touchid install uninstall clean age

build:
	swift build -c release --product $(BINARY)

# Unit and integration tests (OpenSSH as oracle). Needs an unlocked Mac.
# `swift build` first: the suite also drives the CLI binary.
test:
	swift build
	swift run -q touchid-ssh-agent-selftest

# Adds a real SSH login against a throwaway sshd container. Needs Docker.
test-docker:
	swift build
	swift run -q touchid-ssh-agent-selftest --docker

# Interactive: asks you to approve one Touch ID prompt and refuse another,
# with the agent running under launchd like the installed one.
test-touchid: build
	scripts/manual-touchid-test.sh .build/release/$(BINARY)

# Copies the binary to $(PREFIX)/bin. Register the agent afterwards with
# `$(PREFIX)/bin/touchid-ssh-agent install`.
install: build age
	install -d "$(PREFIX)/bin"
	install -m 0755 ".build/release/$(BINARY)" "$(PREFIX)/bin/$(BINARY)"
	@echo "Installed at $(PREFIX)/bin/$(BINARY)"

# age encrypts the inventory backup. Installed with Homebrew when missing;
# without Homebrew, only a warning (the agent itself works without age).
age:
	@if command -v age >/dev/null 2>&1; then \
		echo "age: $$(command -v age)"; \
	elif command -v brew >/dev/null 2>&1; then \
		echo "Installing age with Homebrew (needed for the inventory backup)..."; \
		brew install age; \
	else \
		echo "Warning: age is not installed and Homebrew was not found."; \
		echo "Install age (https://age-encryption.org) so the inventory backup can be written."; \
	fi

uninstall:
	-"$(PREFIX)/bin/$(BINARY)" uninstall
	rm -f "$(PREFIX)/bin/$(BINARY)"

clean:
	swift package clean
