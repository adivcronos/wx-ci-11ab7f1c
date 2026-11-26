import 'dart:io';

import '../config.dart';
import 'app_paths.dart';

/// "You've been updated" notice for the VPN screen.
///
/// The app updates itself silently now, so tell the user once that it
/// happened. Decided ONCE per launch, at first use:
///  * `last_version` holds the version that last ran; if it differs from this
///    build, we were just updated.
///  * Builds before 6.5.6 never wrote that file, so on the first run of this
///    build a missing file plus an existing saved login (`config.enc`) also
///    counts as an update (a fresh install has no saved login).
/// The file is rewritten straight away, so the notice shows for one launch.
class UpdatedNotice {
  static bool _decided = false;
  static String? _version;

  /// The new version to announce, or null.
  static String? get version {
    if (!_decided) {
      _decided = true;
      _version = _decide();
    }
    return _version;
  }

  /// True when dotted version [a] is strictly newer than [b]. A leading 'v'
  /// and any suffix after the numbers ("-test", "+68") are ignored.
  static bool isNewer(String a, String b) {
    List<int> parts(String v) {
      var t = v.trim();
      if (t.startsWith('v') || t.startsWith('V')) t = t.substring(1);
      final m = RegExp(r'^\d+(\.\d+)*').firstMatch(t);
      if (m == null) return const [];
      return m.group(0)!.split('.').map(int.parse).toList();
    }

    final pa = parts(a), pb = parts(b);
    if (pa.isEmpty || pb.isEmpty) return false;
    for (var i = 0; i < (pa.length > pb.length ? pa.length : pb.length); i++) {
      final x = i < pa.length ? pa[i] : 0, y = i < pb.length ? pb[i] : 0;
      if (x != y) return x > y;
    }
    return false;
  }

  /// Hide it for the rest of this launch.
  static void dismiss() => _version = null;

  static String? _decide() {
    const current = AppConfig.appVersion;
    try {
      final f = File(AppPaths.file('last_version'));
      final hadFile = f.existsSync();
      final last = hadFile ? f.readAsStringSync().trim() : '';
      final hasLogin = File(AppPaths.file('config.enc')).existsSync();
      Directory(AppPaths.dataDir()).createSync(recursive: true);
      f.writeAsStringSync(current);
      // Only a real upgrade: a rollback / same build must never claim
      // "updated to the newest version".
      if (hadFile) {
        return last.isNotEmpty && isNewer(current, last) ? current : null;
      }
      return hasLogin ? current : null;
    } catch (_) {
      return null;
    }
  }
}
