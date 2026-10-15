import Darwin
import Foundation

public enum FileLockError: Error, CustomStringConvertible {
    case cannotOpen(String, String)
    case timedOut(String)

    public var description: String {
        switch self {
        case .cannotOpen(let path, let reason): return "cannot open lock file \(path): \(reason)"
        case .timedOut(let path): return "another touchid-ssh-agent command holds \(path); try again in a moment"
        }
    }
}

/// An advisory `flock` on a private lock file, shared by every process of this
/// user that runs touchid-ssh-agent. The lock is released when the descriptor
/// closes, so a crashed holder never leaves it stuck.
public enum FileLock {
    /// Runs `body` while holding an exclusive lock on `url`. With a `timeout`,
    /// gives up after that many seconds; without one, waits as long as needed.
    public static func withLock<T>(_ url: URL, timeout: TimeInterval? = nil, _ body: () throws -> T) throws -> T {
        let fd = try acquire(url, timeout: timeout)
        defer {
            flock(fd, LOCK_UN)
            close(fd)
        }
        return try body()
    }

    /// Acquires the lock and returns its descriptor; `release` (or process exit) frees it.
    public static func acquire(_ url: URL, timeout: TimeInterval? = nil) throws -> Int32 {
        let fd = open(url.path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw FileLockError.cannotOpen(url.path, String(cString: strerror(errno))) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == getuid() else {
            close(fd)
            throw FileLockError.cannotOpen(url.path, "not a regular file owned by this user")
        }
        guard let timeout else {
            while flock(fd, LOCK_EX) != 0 {
                guard errno == EINTR else {
                    let reason = String(cString: strerror(errno))
                    close(fd)
                    throw FileLockError.cannotOpen(url.path, reason)
                }
            }
            return fd
        }
        let deadline = Date().addingTimeInterval(timeout)
        while flock(fd, LOCK_EX | LOCK_NB) != 0 {
            guard errno == EWOULDBLOCK || errno == EINTR, Date() < deadline else {
                close(fd)
                throw FileLockError.timedOut(url.path)
            }
            usleep(50_000)
        }
        return fd
    }

    public static func release(_ fd: Int32) {
        flock(fd, LOCK_UN)
        close(fd)
    }
}
