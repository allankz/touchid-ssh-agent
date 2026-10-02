import Darwin
import Foundation

/// Minimal interactive helpers for the guided commands.
enum Terminal {
    static var isInteractive: Bool { isatty(STDIN_FILENO) == 1 && isatty(STDOUT_FILENO) == 1 }

    static func requireInteractive(_ command: String) throws {
        guard isInteractive else {
            throw UsageError(description: "`\(tool) \(command)` needs an interactive terminal.")
        }
    }

    /// Visible input. Returns nil at end of input.
    static func ask(_ prompt: String) -> String? {
        print(prompt, terminator: "")
        fflush(stdout)
        return readLine(strippingNewline: true)
    }

    /// Hidden input read from the terminal, never echoed.
    static func askHidden(_ prompt: String) -> String? {
        var buffer = [CChar](repeating: 0, count: 1024)
        defer { memset_s(&buffer, buffer.count, 0, buffer.count) }
        guard readpassphrase(prompt, &buffer, buffer.count, RPP_ECHO_OFF | RPP_REQUIRE_TTY) != nil else {
            return nil
        }
        return String(cString: buffer)
    }

    /// Asks until the user types `word` (case-insensitive) or `cancelWord`.
    /// Returns false when the user cancels or input ends.
    static func confirm(word: String, cancelWord: String? = nil, prompt: String) -> Bool {
        while let answer = ask(prompt)?.trimmingCharacters(in: .whitespaces) {
            if answer.caseInsensitiveCompare(word) == .orderedSame { return true }
            if let cancelWord, answer.caseInsensitiveCompare(cancelWord) == .orderedSame { return false }
        }
        return false
    }

    /// Clears the screen and the scrollback, so a passphrase does not stay visible.
    static func clearScreen() {
        guard isatty(STDOUT_FILENO) == 1 else { return }
        print("\u{1b}[2J\u{1b}[3J\u{1b}[H", terminator: "")
        fflush(stdout)
    }

    static func heading(_ text: String) {
        print("\n\(text)\n\(String(repeating: "─", count: text.count))")
    }

    /// Quotes a path for a shell command shown to the user (paths may contain spaces).
    /// A leading `~/` stays unquoted so the shell still expands it.
    static func shellQuoted(_ text: String) -> String {
        if text.hasPrefix("~/") { return "~/" + shellQuoted(String(text.dropFirst(2))) }
        return text.contains(where: { " '\"$\\".contains($0) })
            ? "'" + text.replacingOccurrences(of: "'", with: "'\\''") + "'"
            : text
    }
}
