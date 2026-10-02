import Darwin
import Foundation

/// Human-facing output: a left margin, some breathing room and light styling.
/// Machine-readable commands (pubkey, fingerprint, config) keep using print.
enum Out {
    static let margin = "  "

    /// Colors and bold only on a real terminal, and never with NO_COLOR set.
    static var styled: Bool {
        isatty(STDOUT_FILENO) == 1 && ProcessInfo.processInfo.environment["NO_COLOR"] == nil
    }

    static func style(_ text: String, _ code: String) -> String {
        styled ? "\u{1b}[\(code)m\(text)\u{1b}[0m" : text
    }

    static func bold(_ text: String) -> String { style(text, "1") }
    static func dim(_ text: String) -> String { style(text, "2") }
    static func accent(_ text: String) -> String { style(text, "1;36") }

    /// Prints `text` with the margin on every non-empty line.
    static func say(_ text: String = "") {
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false)
        print(lines.map { $0.isEmpty ? "" : margin + $0 }.joined(separator: "\n"))
    }

    static let logo = [
        #" _                    _     _     _ "#,
        #"| |_  ___  _  _  __  | |_  (_) __| |"#,
        #"|  _|/ _ \| || |/ _| | ' \ | |/ _` |"#,
        #" \__|\___/ \_,_|\__| |_||_||_|\__,_|"#,
    ]

    /// ASCII header for the guided commands.
    static func header(_ command: String, _ subtitle: String) {
        for (index, row) in logo.enumerated() {
            print(margin + accent(row) + (index == logo.count - 1 ? dim("  ssh-agent") : ""))
        }
        print("")
        say(bold(command) + dim(" · \(subtitle)"))
        print("")
    }

    static func section(_ title: String) {
        print("")
        say(bold(title))
        say(dim(String(repeating: "─", count: title.count)))
    }

    /// Shows a value in a highlighted box, e.g. the emergency passphrase.
    static func boxed(_ text: String) {
        let width = text.count + 8
        let indent = margin + "   "
        let lines = [
            "╭" + String(repeating: "─", count: width) + "╮",
            "│" + String(repeating: " ", count: width) + "│",
            "│    " + text + "    │",
            "│" + String(repeating: " ", count: width) + "│",
            "╰" + String(repeating: "─", count: width) + "╯",
        ]
        print("")
        for line in lines { print(indent + accent(line)) }
        print("")
    }
}
