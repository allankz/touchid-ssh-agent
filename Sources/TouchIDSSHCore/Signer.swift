import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// Why a signature was not produced. Every case means "no signature".
public enum SignError: Error, Equatable, CustomStringConvertible {
    case canceled
    case timedOut
    case biometryLockout
    case biometryUnavailable
    case biometryNotEnrolled
    case authenticationFailed
    case deviceLocked
    case keyUnusable(String)

    /// Short token for the event log.
    public var logCode: String {
        switch self {
        case .canceled: return "canceled"
        case .timedOut: return "timeout"
        case .biometryLockout: return "lockout"
        case .biometryUnavailable: return "unavailable"
        case .biometryNotEnrolled: return "not-enrolled"
        case .authenticationFailed: return "auth-failed"
        case .deviceLocked: return "locked"
        case .keyUnusable: return "key-error"
        }
    }

    public var description: String {
        switch self {
        case .canceled:
            return "Signature denied in the Touch ID prompt."
        case .timedOut:
            return "Nobody approved Touch ID in time; signature denied."
        case .biometryLockout:
            return "Touch ID is locked out. Lock the screen (⌃⌘Q) and unlock it with your Mac password to re-enable it."
        case .biometryUnavailable:
            return "Touch ID unavailable (lid closed, no sensor, or no graphical session)."
        case .biometryNotEnrolled:
            return "No fingerprints are enrolled in Touch ID."
        case .authenticationFailed:
            return "Fingerprint not recognized."
        case .deviceLocked:
            return "The Mac is locked; unlock the screen to authorize signatures."
        case .keyUnusable(let detail):
            return "The key could not be used (changing fingerprints invalidates a current-set key): \(detail)"
        }
    }
}

public enum SecureEnclaveSigner {
    public static let defaultPromptTimeout: TimeInterval = 60

    /// Signs `data` with the identity and returns the SSH signature blob.
    ///
    /// A fresh `LAContext` is created for every call and never reused, so the
    /// Secure Enclave asks for Touch ID on every signature. The prompt is
    /// cancelled after `timeout` seconds.
    public static func sign(
        _ data: Data,
        with identity: StoredIdentity,
        reason: String,
        timeout: TimeInterval = defaultPromptTimeout
    ) throws -> Data {
        let context = LAContext()
        context.localizedReason = reason
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedCancelTitle = "Deny"
        // Biometry-only policy: hide the "Use Password" button.
        context.localizedFallbackTitle = ""

        let timer = DispatchWorkItem { [weak context] in context?.invalidate() }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: timer)
        defer {
            timer.cancel()
            context.invalidate()
        }

        do {
            let key = try SecureEnclave.P256.Signing.PrivateKey(
                dataRepresentation: identity.wrappedKey,
                authenticationContext: context
            )
            let signature = try key.signature(for: data)
            // Defense in depth: never hand out a signature that does not verify.
            guard identity.publicKey.isValidSignature(signature, for: data) else {
                throw SignError.keyUnusable("signature does not match the public key")
            }
            return try SSHKeyFormat.signatureBlob(rawRS: signature.rawRepresentation)
        } catch let error as SignError {
            throw error
        } catch {
            throw map(error)
        }
    }

    static func map(_ error: Error) -> SignError {
        let nsError = error as NSError
        if nsError.domain == NSOSStatusErrorDomain, nsError.code == Int(errSecInteractionNotAllowed) {
            return .deviceLocked
        }
        guard nsError.domain == LAErrorDomain else {
            return .keyUnusable(nsError.localizedDescription)
        }
        switch LAError.Code(rawValue: nsError.code) {
        case .userCancel, .userFallback, .systemCancel:
            return .canceled
        case .appCancel, .invalidContext:
            // Only the timeout timer invalidates the context while a prompt is up.
            return .timedOut
        case .biometryLockout:
            return .biometryLockout
        case .biometryNotAvailable, .notInteractive:
            return .biometryUnavailable
        case .biometryNotEnrolled:
            return .biometryNotEnrolled
        case .authenticationFailed:
            return .authenticationFailed
        default:
            return .keyUnusable(nsError.localizedDescription)
        }
    }
}
