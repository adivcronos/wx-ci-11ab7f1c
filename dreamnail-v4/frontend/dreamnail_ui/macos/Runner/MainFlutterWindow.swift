import Cocoa
import FlutterMacOS

class MainFlutterWindow: NSWindow {
  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    let windowFrame = self.frame
    self.contentViewController = flutterViewController
    self.setFrame(windowFrame, display: true)

    RegisterGeneratedPlugins(registry: flutterViewController)

    // Quit / logout / shutdown: disconnect the engine first so the system
    // proxy isn't left pointing at a dead local port (only the tray "Quit"
    // used to). Stealth mode already self-heals via the helper's watchdog.
    NotificationCenter.default.addObserver(
      forName: NSApplication.willTerminateNotification, object: nil, queue: nil
    ) { _ in
      disconnectEngineForExit()
    }

    super.awakeFromNib()
  }
}

/// Ask the Rust engine (Frameworks/libdreamnail_ffi.dylib, loaded by Dart FFI)
/// to disconnect, bounded to ~8s so a busy engine can't stall termination.
private func disconnectEngineForExit() {
  guard let fw = Bundle.main.privateFrameworksPath else { return }
  guard let handle = dlopen(fw + "/libdreamnail_ffi.dylib", RTLD_NOW | RTLD_NOLOAD) else {
    return
  }
  typealias RequestFn = @convention(c) (UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?
  typealias FreeFn = @convention(c) (UnsafeMutablePointer<CChar>?) -> Void
  guard let reqSym = dlsym(handle, "dn_request") else { return }
  let request = unsafeBitCast(reqSym, to: RequestFn.self)
  let freeSym = dlsym(handle, "dn_free_string")
  let done = DispatchSemaphore(value: 0)
  DispatchQueue.global(qos: .userInitiated).async {
    let reply = "{\"method\":\"disconnect\",\"args\":{}}".withCString { request($0) }
    if let reply = reply, let freeSym = freeSym {
      unsafeBitCast(freeSym, to: FreeFn.self)(reply)
    }
    done.signal()
  }
  _ = done.wait(timeout: .now() + 8)
}
