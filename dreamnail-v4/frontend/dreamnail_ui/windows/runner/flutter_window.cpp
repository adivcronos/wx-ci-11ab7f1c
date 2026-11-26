#include "flutter_window.h"

#include <optional>

#include "flutter/generated_plugin_registrant.h"

namespace {

// The engine DLL (dreamnail_ffi.dll) is loaded by Dart FFI; call its
// `disconnect` directly so a forced quit never leaves Windows pointed at a
// proxy / tunnel that's about to vanish. Run on a worker thread with a bound so
// a busy engine can't hang shutdown (Windows would then kill us anyway).
DWORD WINAPI DisconnectThread(LPVOID) {
  HMODULE dll = GetModuleHandleW(L"dreamnail_ffi.dll");
  if (!dll) {
    return 0;
  }
  using RequestFn = char* (*)(const char*);
  using FreeFn = void (*)(char*);
  auto request = reinterpret_cast<RequestFn>(
      reinterpret_cast<void*>(GetProcAddress(dll, "dn_request")));
  auto free_str = reinterpret_cast<FreeFn>(
      reinterpret_cast<void*>(GetProcAddress(dll, "dn_free_string")));
  if (!request) {
    return 0;
  }
  char* reply = request("{\"method\":\"disconnect\",\"args\":{}}");
  if (reply && free_str) {
    free_str(reply);
  }
  return 0;
}

void DisconnectEngineForExit() {
  HANDLE t = CreateThread(nullptr, 0, DisconnectThread, nullptr, 0, nullptr);
  if (t) {
    WaitForSingleObject(t, 8000);
    CloseHandle(t);
  }
}

}  // namespace

FlutterWindow::FlutterWindow(const flutter::DartProject& project)
    : project_(project) {}

FlutterWindow::~FlutterWindow() {}

bool FlutterWindow::OnCreate() {
  if (!Win32Window::OnCreate()) {
    return false;
  }

  RECT frame = GetClientArea();

  // The size here must match the window dimensions to avoid unnecessary surface
  // creation / destruction in the startup path.
  flutter_controller_ = std::make_unique<flutter::FlutterViewController>(
      frame.right - frame.left, frame.bottom - frame.top, project_);
  // Ensure that basic setup of the controller was successful.
  if (!flutter_controller_->engine() || !flutter_controller_->view()) {
    return false;
  }
  RegisterPlugins(flutter_controller_->engine());
  SetChildContent(flutter_controller_->view()->GetNativeWindow());

  flutter_controller_->engine()->SetNextFrameCallback([&]() {
    this->Show();
  });

  // Flutter can complete the first frame before the "show window" callback is
  // registered. The following call ensures a frame is pending to ensure the
  // window is shown. It is a no-op if the first frame hasn't completed yet.
  flutter_controller_->ForceRedraw();

  return true;
}

void FlutterWindow::OnDestroy() {
  if (flutter_controller_) {
    flutter_controller_ = nullptr;
  }

  Win32Window::OnDestroy();
}

LRESULT
FlutterWindow::MessageHandler(HWND hwnd, UINT const message,
                              WPARAM const wparam,
                              LPARAM const lparam) noexcept {
  // Windows asking the whole app to quit: an installer's Restart Manager
  // (upgrade / uninstall), logoff or shutdown. Handled BEFORE the plugins see
  // it: "close to tray" (window_manager preventClose) used to swallow every
  // polite close, so an installer could never shut the old version down and
  // its locked files broke the upgrade. Say yes, disconnect cleanly (restores
  // the system proxy / stealth routing), then exit for real.
  if (message == WM_QUERYENDSESSION) {
    return TRUE;
  }
  if (message == WM_ENDSESSION) {
    if (wparam) {
      DisconnectEngineForExit();
      ExitProcess(0);
    }
    return 0;
  }

  // Give Flutter, including plugins, an opportunity to handle window messages.
  if (flutter_controller_) {
    std::optional<LRESULT> result =
        flutter_controller_->HandleTopLevelWindowProc(hwnd, message, wparam,
                                                      lparam);
    if (result) {
      return *result;
    }
  }

  switch (message) {
    case WM_FONTCHANGE:
      flutter_controller_->engine()->ReloadSystemFonts();
      break;
  }

  return Win32Window::MessageHandler(hwnd, message, wparam, lparam);
}
