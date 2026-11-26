import 'dart:io';

/// Plain-English, per-OS "what to do when the update opens" steps. Shown in
/// every update prompt (optional banner dialog, required-update banner) so a
/// customer is never left guessing what the installer window wants.
///
/// Most installs are silent (the app closes and reopens by itself); these steps
/// cover the times the system shows a window instead.
bool get _isAppImage =>
    (Platform.environment['APPIMAGE'] ?? '').isNotEmpty ||
    (Platform.environment['APPDIR'] ?? '').isNotEmpty;

/// One short line, for banners.
String updateStepShort() {
  if (Platform.isMacOS) {
    return 'Mac: in the window that opens, drag Weather onto Applications and choose Replace.';
  }
  if (Platform.isWindows) {
    return 'Windows: click Yes when asked, then wait — the app reopens by itself.';
  }
  if (Platform.isLinux && _isAppImage) {
    return 'Linux: it installs by itself — the app closes and reopens.';
  }
  if (Platform.isLinux) {
    return 'Linux: if a password box appears, enter your computer password — the app reopens by itself.';
  }
  return 'Follow the installer, then reopen the app.';
}

/// Numbered steps, for the update details dialog (terminal-style lines).
List<String> updateSteps() {
  if (Platform.isMacOS) {
    return const [
      '1. click Install — a window with Weather and Applications opens',
      '2. drag Weather onto the Applications folder',
      '3. when asked, choose Replace (enter your Mac password if asked)',
      '4. open Weather from Applications (not the download window)',
    ];
  }
  if (Platform.isWindows) {
    return const [
      '1. click Install',
      '2. if Windows asks "allow this app to make changes?", click Yes',
      '3. wait — the app closes and reopens by itself',
    ];
  }
  if (Platform.isLinux && _isAppImage) {
    return const [
      '1. click Install',
      '2. wait — the app closes and reopens by itself',
    ];
  }
  if (Platform.isLinux) {
    return const [
      '1. click Install',
      '2. if a password box appears, enter your computer password',
      '3. if a software window opens instead, click Install there',
      '4. wait — the app reopens by itself',
    ];
  }
  return const ['1. click Install and follow the installer'];
}
