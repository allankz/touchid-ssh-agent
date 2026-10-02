PREFIX ?= $(HOME)/.local
BINARY := touchid-ssh-agent

.PHONY: build test test-docker test-touchid install uninstall clean

build:
	swift build -c release --product $(BINARY)

# Unit and integration tests (OpenSSH as oracle). Needs an unlocked Mac.
test:
	swift run -q touchid-ssh-agent-selftest

# Adds a real SSH login against a throwaway sshd container. Needs Docker.
test-docker:
	swift run -q touchid-ssh-agent-selftest --docker

# Interactive: asks you to approve one Touch ID prompt and refuse another,
# with the agent running under launchd like the installed one.
test-touchid: build
	scripts/manual-touchid-test.sh .build/release/$(BINARY)

# Copies the binary to $(PREFIX)/bin. Register the agent afterwards with
# `$(PREFIX)/bin/touchid-ssh-agent install`.
install: build
	install -d "$(PREFIX)/bin"
	install -m 0755 ".build/release/$(BINARY)" "$(PREFIX)/bin/$(BINARY)"
	@echo "Installed at $(PREFIX)/bin/$(BINARY)"

uninstall:
	-"$(PREFIX)/bin/$(BINARY)" uninstall
	rm -f "$(PREFIX)/bin/$(BINARY)"

clean:
	swift package clean
