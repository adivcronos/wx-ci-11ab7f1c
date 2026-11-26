import 'package:flutter/material.dart';

import '../api.dart';
import '../theme.dart';

/// "Report a problem" — one CRT-styled dialog shared by every entry point: the
/// HELP button on the VPN screen, the "send a report" link on a connect-failure
/// banner, and the link in settings. Collects a note and hands it to the engine,
/// which attaches a diagnostics bundle and sends it to support — or, if it can't
/// be delivered right now (not connected yet, school network blocking the
/// server), saves it and sends it automatically on the next successful connect.
///
/// [prefill] seeds the note (e.g. the error the customer just saw) so a report
/// from a failure banner already says what went wrong.
Future<void> showReportDialog(
  BuildContext context,
  ApiClient api, {
  String prefill = '',
}) async {
  final controller = TextEditingController(text: prefill);
  controller.selection = TextSelection.collapsed(offset: prefill.length);
  bool sending = false;
  String? error;
  final messenger = ScaffoldMessenger.maybeOf(context);
  await showDialog<void>(
    context: context,
    barrierColor: Colors.black54,
    builder: (ctx) => StatefulBuilder(
      builder: (ctx, setLocal) => Dialog(
        backgroundColor: PxColors.surface,
        shape: RoundedRectangleBorder(
          side: const BorderSide(color: PxColors.frame),
          borderRadius: BorderRadius.circular(8),
        ),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 460),
          child: Padding(
            padding: const EdgeInsets.all(18),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'REPORT A PROBLEM',
                  style: TextStyle(
                    fontFamily: PxFont.hero,
                    fontWeight: FontWeight.w700,
                    fontSize: 15,
                    letterSpacing: 1.5,
                    color: PxColors.accent,
                    shadows: glowText(PxColors.accent, alpha: 0.3),
                  ),
                ),
                const SizedBox(height: 8),
                const Text(
                  'what went wrong? a quick diagnostic is attached automatically '
                  '(no browsing, no passwords). if it can\'t be sent right now, '
                  'it\'s saved and sent the next time you connect.',
                  style: _note,
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: controller,
                  maxLines: 5,
                  maxLength: 1000,
                  autofocus: true,
                  style: const TextStyle(
                    fontFamily: PxFont.body,
                    fontSize: 13,
                    color: PxColors.textPrimary,
                  ),
                  decoration: InputDecoration(
                    hintText: 'e.g. it won\'t connect on my school wifi…',
                    hintStyle: const TextStyle(color: PxColors.mutedDeep, fontSize: 13),
                    filled: true,
                    fillColor: PxColors.field,
                    enabledBorder: OutlineInputBorder(
                      borderSide: const BorderSide(color: PxColors.frameInset),
                      borderRadius: BorderRadius.circular(6),
                    ),
                    focusedBorder: OutlineInputBorder(
                      borderSide: const BorderSide(color: PxColors.accent),
                      borderRadius: BorderRadius.circular(6),
                    ),
                  ),
                ),
                if (error != null) ...[
                  const SizedBox(height: 6),
                  Text(error!, style: const TextStyle(color: PxColors.danger, fontSize: 12)),
                ],
                const SizedBox(height: 10),
                Row(
                  mainAxisAlignment: MainAxisAlignment.end,
                  children: [
                    _link('cancel', () => Navigator.of(ctx).pop()),
                    const SizedBox(width: 18),
                    _link(
                      sending ? 'sending…' : 'send',
                      () async {
                        if (sending) return;
                        final msg = controller.text.trim();
                        if (msg.isEmpty) {
                          setLocal(() => error = 'please type a short note first.');
                          return;
                        }
                        setLocal(() {
                          sending = true;
                          error = null;
                        });
                        Map<String, dynamic> r;
                        try {
                          r = await api.reportProblem(msg);
                        } catch (_) {
                          r = {'success': false, 'error': 'could not send right now.'};
                        }
                        if (r['success'] == true) {
                          if (ctx.mounted) Navigator.of(ctx).pop();
                          messenger?.showSnackBar(
                            SnackBar(
                              content: Text(
                                r['queued'] == true
                                    ? 'Saved — it\'ll be sent to support next time you connect.'
                                    : 'Report sent — thank you.',
                              ),
                            ),
                          );
                        } else {
                          setLocal(() {
                            sending = false;
                            error = (r['error'] as String?) ?? 'could not send right now.';
                          });
                        }
                      },
                      color: PxColors.accent,
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    ),
  );
}

const _note = TextStyle(
  fontFamily: PxFont.body,
  fontSize: 12,
  height: 1.4,
  color: PxColors.mutedDeep,
);

Widget _link(String label, VoidCallback onTap, {Color color = PxColors.textMuted}) =>
    MouseRegion(
      cursor: SystemMouseCursors.click,
      child: GestureDetector(
        behavior: HitTestBehavior.opaque,
        onTap: onTap,
        child: Text(
          '> $label',
          style: TextStyle(fontFamily: PxFont.body, fontSize: 12, color: color),
        ),
      ),
    );
