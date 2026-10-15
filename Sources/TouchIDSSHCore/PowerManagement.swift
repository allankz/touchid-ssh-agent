import Foundation
import IOKit
import IOKit.pwr_mgt

/// Keeps the Mac from idle-sleeping while a grant is active, like `caffeinate -i`
/// (which, unlike `caffeinate -s`, also works on battery). The display may still
/// sleep and the screen may still lock. Closing the lid, a forced sleep or a
/// loss of power are not prevented.
public final class IdleSleepAssertion {
    private var id = IOPMAssertionID(0)
    private var held = false
    private let lock = NSLock()

    public init?(reason: String) {
        let result = IOPMAssertionCreateWithName(
            kIOPMAssertionTypePreventUserIdleSystemSleep as CFString,
            IOPMAssertionLevel(kIOPMAssertionLevelOn), reason as CFString, &id)
        guard result == kIOReturnSuccess else { return nil }
        held = true
    }

    deinit { release() }

    public func release() {
        lock.lock()
        defer { lock.unlock() }
        guard held else { return }
        held = false
        IOPMAssertionRelease(id)
    }
}

/// Calls `handler` when the Mac wakes from sleep, so a grant re-checks its
/// deadline right away instead of waiting for its next timer. It never delays
/// or vetoes sleep.
public final class WakeObserver {
    // IOKit power messages (iokit_common_msg values from IOMessage.h).
    static let canSystemSleep: UInt32 = 0xE000_0270
    static let systemWillSleep: UInt32 = 0xE000_0280
    static let systemHasPoweredOn: UInt32 = 0xE000_0300

    fileprivate let handler: () -> Void
    fileprivate var rootPort: io_connect_t = 0
    private var notifier: io_object_t = 0
    private var port: IONotificationPortRef?
    private var thread: Thread?
    private var runLoop: CFRunLoop?
    private let ready = DispatchSemaphore(value: 0)

    public init(handler: @escaping () -> Void) {
        self.handler = handler
        let thread = Thread { [weak self] in self?.run() }
        thread.name = "touchid-ssh-agent.wake"
        self.thread = thread
        thread.start()
        ready.wait()
    }

    deinit { stop() }

    private func run() {
        let context = Unmanaged.passUnretained(self).toOpaque()
        rootPort = IORegisterForSystemPower(context, &port, { context, _, message, argument in
            guard let context else { return }
            let observer = Unmanaged<WakeObserver>.fromOpaque(context).takeUnretainedValue()
            switch message {
            case WakeObserver.canSystemSleep, WakeObserver.systemWillSleep:
                IOAllowPowerChange(observer.rootPort, Int(bitPattern: argument))
            case WakeObserver.systemHasPoweredOn:
                observer.handler()
            default:
                break
            }
        }, &notifier)
        runLoop = CFRunLoopGetCurrent()
        if rootPort != 0, let port {
            CFRunLoopAddSource(runLoop, IONotificationPortGetRunLoopSource(port).takeUnretainedValue(), .defaultMode)
        }
        ready.signal()
        if rootPort != 0 { CFRunLoopRun() }
    }

    public func stop() {
        guard rootPort != 0 else { return }
        if let runLoop { CFRunLoopStop(runLoop) }
        IODeregisterForSystemPower(&notifier)
        IOServiceClose(rootPort)
        if let port { IONotificationPortDestroy(port) }
        rootPort = 0
        port = nil
    }
}
