//! Persistent elevation — "ask for admin once, then never again".
//!
//! Stealth mode needs the privileged TUN helper launched as root/admin. By
//! default the OS asks for the admin password every time the app starts (see
//! `tun.rs` `spawn_elevated`). When the user opts in, we install a small,
//! PERMANENT, NARROWLY-SCOPED system rule so that one specific helper binary can
//! be launched without a password — the approach shipped by mainstream desktop
//! VPNs, and deliberately the opposite of malware:
//!
//!   * Consent is one real admin prompt, driven by the OS — the app never sees
//!     or handles the password.
//!   * What we install is NAMED and DISCOVERABLE (a polkit rule / a sudoers file /
//!     a Scheduled Task), visible in the OS's own tools and removable. Hiding it
//!     is what would make this a rootkit, so we don't.
//!   * It grants the NARROWEST capability: passwordless launch of EXACTLY the
//!     shipped helper binary, for the installing user — never a general root shell
//!     or arbitrary-program exec.
//!   * It is removable: `uninstall()` deletes it (one more admin prompt).
//!
//! Per OS:
//!   * Linux   — a polkit JS rule (`/etc/polkit-1/rules.d/…`) allowing passwordless
//!     `pkexec` of just the helper for this user in a local active session.
//!   * macOS   — a `sudoers.d` rule (`/etc/sudoers.d/…`) allowing `sudo -n` of just
//!     the helper for this user.
//!   * Windows — a Scheduled Task that runs the helper elevated AS THIS SAME USER
//!     (their admin token, `RunLevel Highest`), which the app triggers with
//!     `schtasks /run` and no UAC prompt. Per-connect parameters ride in a fixed
//!     args-file so the task's action stays fixed and simple.
//!
//! Windows note: this only helps a user who is a local ADMIN (only they have an
//! elevated token for the task to use). A standard user can never self-elevate, so
//! there `install()` will simply fail and the app keeps prompting — no worse than
//! before.

use std::path::Path;
use std::process::Child;

use dreamnail_core::ports::{EngineError, Result};

/// True when a "remember admin" mechanism exists AND can be done SAFELY here.
///
/// Linux needs the modern polkit JS-rules backend (polkit ≥ 0.106), detected by
/// `/etc/polkit-1/rules.d`. That backend is the only one that can scope
/// passwordless launch to EXACTLY our helper; the legacy `.pkla` backend can only
/// grant passwordless pkexec for a whole action (every program), which would be
/// passwordless root for the user, so we refuse it and the feature stays hidden.
/// macOS (sudoers) and Windows (Scheduled Task) can always scope to the helper.
pub fn supported() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new("/etc/polkit-1/rules.d").is_dir()
    }
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        true
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        false
    }
}

/// The current user, validated. Unix: `$USER`. Only ASCII word/·-. characters, so
/// it can be embedded in a rule without escaping surprises.
#[cfg(unix)]
fn current_user() -> Result<String> {
    std::env::var("USER")
        .ok()
        .filter(|u| {
            !u.is_empty() && u.chars().all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c))
        })
        .ok_or_else(|| EngineError::Proxy("could not determine the current user".into()))
}

// ==========================================================================
// Pure, OS-independent string builders (unit-tested on any host).
// ==========================================================================

/// The polkit rule (Linux). Passwordless ONLY when the action is pkexec's
/// program-exec action, the program is exactly our helper, and the caller is the
/// installing user in a LOCAL ACTIVE session; anything else falls through to
/// polkit's normal password handling.
pub(crate) fn polkit_rule_text(helper: &Path, user: &str) -> String {
    let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        "// Dreamnail stealth helper — passwordless root launch for one user.\n\
         // Installed by the app when \"remember admin\" is enabled; delete this\n\
         // file (or toggle the setting off) to require the password again.\n\
         polkit.addRule(function(action, subject) {{\n\
         \x20   if (action.id == \"org.freedesktop.policykit.exec\" &&\n\
         \x20       action.lookup(\"program\") == \"{prog}\" &&\n\
         \x20       subject.user == \"{user}\" &&\n\
         \x20       subject.local && subject.active) {{\n\
         \x20       return polkit.Result.YES;\n\
         \x20   }}\n\
         }});\n",
        prog = esc(&helper.to_string_lossy()),
        user = esc(user),
    )
}

#[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
/// The sudoers rule (macOS): NOPASSWD for exactly this user running exactly this
/// helper. sudoers is line-oriented and both fields are constrained values.
pub(crate) fn sudoers_content(user: &str, helper: &Path) -> String {
    format!(
        "# Dreamnail stealth helper — passwordless root launch for one user.\n\
         # Installed by the app when \"remember admin\" is on; remove this file\n\
         # (or toggle the setting off) to require the password again.\n\
         {user} ALL=(root) NOPASSWD: {prog}\n",
        user = user,
        prog = helper.to_string_lossy(),
    )
}

#[cfg_attr(not(any(test, target_os = "windows")), allow(dead_code))]
/// The PowerShell that registers the fixed Scheduled Task (Windows). The task's
/// action is `helper --args-file "<fixed>"` — one simple, fixed argument — and it
/// runs as `user` with their elevated token, so `schtasks /run` needs no UAC.
pub(crate) fn windows_install_script(user: &str, helper: &Path, args_file: &Path, task: &str) -> String {
    let q = |s: &str| s.replace('\'', "''"); // ' -> '' inside a PS '...' literal
    format!(
        "$ErrorActionPreference='Stop';\n\
         $act = New-ScheduledTaskAction -Execute '{exe}' -Argument '--args-file \"{af}\"';\n\
         $prin = New-ScheduledTaskPrincipal -UserId '{user}' -LogonType Interactive -RunLevel Highest;\n\
         $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero);\n\
         Register-ScheduledTask -TaskName '{task}' -Action $act -Principal $prin -Settings $set -Force | Out-Null\n",
        exe = q(&helper.to_string_lossy()),
        af = q(&args_file.to_string_lossy()),
        user = q(user),
        task = task,
    )
}

// ==========================================================================
// Linux — polkit rule + passwordless pkexec.
// ==========================================================================
#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};

    fn rule_path() -> PathBuf {
        PathBuf::from("/etc/polkit-1/rules.d/49-dreamnail-stealth.rules")
    }

    /// A STABLE, root-owned home for the helper, used when the shipped helper
    /// isn't already at a fixed root-owned path (the AppImage / extracted-AppDir
    /// case, where the bundled helper lives at a per-run mount path or under the
    /// user's home). "remember admin" pins the polkit rule to THIS path, so the
    /// grant survives app updates and AppImage re-mounts — and, because it is
    /// root-owned (not user-writable), granting passwordless root launch of it
    /// is safe (a user-writable binary launched as root would be an escalation).
    fn stable_helper_path() -> PathBuf {
        PathBuf::from("/usr/local/lib/dreamnail/dreamnail-tunhelper")
    }

    /// The path the rule pins and the passwordless launch runs. A .deb ships the
    /// helper already root-owned at a fixed path (`/usr/bin/...`) — pin that
    /// directly so apt updates keep working with no re-prompt. Otherwise pin the
    /// stable root-owned copy we install.
    fn effective_helper(bundled: &Path) -> PathBuf {
        use std::os::unix::fs::MetadataExt;
        let root_owned = std::fs::metadata(bundled).map(|m| m.uid() == 0).unwrap_or(false);
        // SECURITY (6.5.5): inside an AppImage's FUSE mount the helper REPORTS
        // uid 0 (squashfs keeps root ownership), so the old uid-only check pinned
        // the passwordless rule to `/tmp/.mount_XXXX/...` — a path any process
        // of this user can recreate once the mount is gone → passwordless root.
        // Only trust the bundled copy for a real system install (.deb under
        // /opt or /usr) that is NOT running from an AppImage / AppDir.
        let under_image =
            std::env::var_os("APPIMAGE").is_some() || std::env::var_os("APPDIR").is_some();
        let system_path = bundled.starts_with("/opt/") || bundled.starts_with("/usr/");
        if root_owned && system_path && !under_image {
            bundled.to_path_buf()
        } else {
            stable_helper_path()
        }
    }

    fn files_equal(a: &Path, b: &Path) -> bool {
        match (std::fs::read(a), std::fs::read(b)) {
            (Ok(x), Ok(y)) => x == y,
            _ => false,
        }
    }

    /// A USER-READABLE record of what we installed, next to the app's own data.
    ///
    /// We can't check installation by reading the polkit rule back: `rules.d` is
    /// `root:polkitd 0750`, so a non-root process gets EPERM — which made the
    /// "remember admin" toggle flip straight back off on every secure distro
    /// (Fedora/Nobara default) even though the rule was installed fine. So on a
    /// successful install we also drop this marker (the helper path it was
    /// installed for) in a place the normal user app can read, and check THAT.
    /// Mirrors the data dir resolution in dreamnail-ffi (`DREAMNAIL_DATA_DIR`
    /// else `$HOME/.dreamnail`) so an elevated relaunch shares the same file.
    fn marker_path() -> PathBuf {
        let base = std::env::var("DREAMNAIL_DATA_DIR")
            .ok()
            .filter(|d| !d.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()))
                    .join(".dreamnail")
            });
        base.join("stealth-remembered")
    }

    pub(super) fn installed(bundled: &Path) -> bool {
        // The marker names the path the rule was pinned to (see `effective_helper`).
        let eff = effective_helper(bundled);
        let marker_ok = match std::fs::read_to_string(marker_path()) {
            Ok(s) => s.trim() == eff.to_string_lossy(),
            Err(_) => false,
        };
        if !marker_ok {
            return false;
        }
        if eff.as_path() == bundled {
            // .deb: the pinned helper IS the shipped one at a fixed root path.
            true
        } else {
            // AppImage / AppDir: we pinned a stable root-owned COPY. It must still
            // exist and match the current build, else an update changed the helper
            // and we re-prompt once to refresh it (same intent as before, but now
            // the path is stable so relaunches of the SAME build stay remembered).
            files_equal(&eff, bundled)
        }
    }

    pub(super) fn install(bundled: &Path) -> Result<()> {
        use std::io::Write;
        let user = current_user()?;
        let eff = effective_helper(bundled);
        let text = polkit_rule_text(&eff, &user);
        let rpath = rule_path();

        // One pkexec = one password. For the .deb case the helper is already a
        // fixed root path, so we only write the rule. Otherwise we first stage the
        // helper to a root-READABLE path as the user (the AppImage mount is not
        // readable by root), then, as root, install it to the stable root-OWNED
        // path AND write the rule — atomically, under the single prompt.
        let status = if eff.as_path() == bundled {
            let mut child = Command::new("pkexec")
                .args(["sh", "-c", "umask 022; cat > \"$1\"", "_", &rpath.to_string_lossy()])
                .stdin(Stdio::piped())
                .spawn()
                .map_err(|e| EngineError::Proxy(format!("could not start pkexec: {e}")))?;
            child
                .stdin
                .take()
                .ok_or_else(|| EngineError::Proxy("pkexec stdin unavailable".into()))?
                .write_all(text.as_bytes())
                .map_err(|e| EngineError::Proxy(format!("writing the rule failed: {e}")))?;
            child.wait().map_err(|e| EngineError::Proxy(format!("pkexec did not complete: {e}")))?
        } else {
            let staged = crate::tun::stage_helper_for_root(bundled)
                .map_err(|e| EngineError::Proxy(format!("staging the helper failed: {e}")))?;
            // $1 staged source, $2 stable dest, $3 rule path; rule text on stdin.
            let script = "set -e; install -D -o root -g root -m 0755 \"$1\" \"$2\"; \
                          umask 022; cat > \"$3\"";
            let mut child = Command::new("pkexec")
                .args([
                    "sh",
                    "-c",
                    script,
                    "_",
                    &staged.to_string_lossy(),
                    &eff.to_string_lossy(),
                    &rpath.to_string_lossy(),
                ])
                .stdin(Stdio::piped())
                .spawn()
                .map_err(|e| EngineError::Proxy(format!("could not start pkexec: {e}")))?;
            child
                .stdin
                .take()
                .ok_or_else(|| EngineError::Proxy("pkexec stdin unavailable".into()))?
                .write_all(text.as_bytes())
                .map_err(|e| EngineError::Proxy(format!("writing the rule failed: {e}")))?;
            child.wait().map_err(|e| EngineError::Proxy(format!("pkexec did not complete: {e}")))?
        };

        if status.success() {
            // Our readable record of what we pinned (see marker_path).
            let marker = marker_path();
            if let Some(dir) = marker.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let _ = std::fs::write(&marker, eff.to_string_lossy().as_bytes());
        }
        prompt_result(status.success())
    }

    pub(super) fn uninstall() -> Result<()> {
        // Nothing to prompt for if we have no record of an install (the rule is
        // root-only, so the marker is our source of truth here).
        let marker = marker_path();
        if !marker.exists() {
            return Ok(());
        }
        // Remove the rule and the stable helper copy (if any) under one prompt.
        let status = Command::new("pkexec")
            .args([
                "rm",
                "-f",
                &rule_path().to_string_lossy(),
                &stable_helper_path().to_string_lossy(),
            ])
            .status()
            .map_err(|e| EngineError::Proxy(format!("could not start pkexec: {e}")))?;
        if status.success() {
            let _ = std::fs::remove_file(&marker);
        }
        prompt_result_off(status.success())
    }

    pub(super) fn spawn_passwordless(bundled: &Path, args: &[String]) -> Option<Result<Child>> {
        if !installed(bundled) {
            return None;
        }
        // Launch the PINNED path (the root-owned copy, or the .deb helper) — that
        // is what the polkit rule authorises passwordlessly.
        let eff = effective_helper(bundled);
        Some(
            Command::new("pkexec")
                .arg(&eff)
                .args(args)
                .spawn()
                .map_err(|e| EngineError::Proxy(format!("could not start pkexec: {e}"))),
        )
    }
}

// ==========================================================================
// macOS — sudoers rule + passwordless `sudo -n`.
// ==========================================================================
#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command};

    fn sudoers_path() -> PathBuf {
        PathBuf::from("/etc/sudoers.d/dreamnail-stealth")
    }

    /// A USER-READABLE record of what we installed, next to the app's own data.
    ///
    /// We can't check installation by reading the sudoers file back:
    /// `/etc/sudoers.d/dreamnail-stealth` is `root:wheel 0440` and the directory
    /// itself is `root:wheel 0750`, so the normal user app gets EPERM on both the
    /// read AND a plain `exists()` — which made the "remember admin" toggle flip
    /// straight back off on macOS, exactly like it did on Linux with the root-only
    /// polkit rule. So on a successful install we also drop this marker (the helper
    /// path it was installed for) where the user app can read it, and check THAT.
    /// Mirrors the data dir resolution in dreamnail-ffi (`DREAMNAIL_DATA_DIR` else
    /// `$HOME/.dreamnail`) so an elevated relaunch shares the same file.
    fn marker_path() -> PathBuf {
        let base = std::env::var("DREAMNAIL_DATA_DIR")
            .ok()
            .filter(|d| !d.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()))
                    .join(".dreamnail")
            });
        base.join("stealth-remembered")
    }

    fn sh_quote(s: &str) -> String {
        format!("'{}'", s.replace('\'', r"'\''"))
    }

    /// SECURITY (6.5.5): the passwordless rule must pin a binary only root can
    /// change. A dragged-in Weather.app is owned by the USER, so pinning the
    /// helper inside it let any process running as the user replace it and get
    /// root. Same fix as Linux 6.5.2: one root-owned copy, refreshed by the
    /// (single) admin prompt whenever the app's helper changes.
    pub(super) fn stable_helper_path() -> PathBuf {
        PathBuf::from("/Library/PrivilegedHelperTools/dreamnail-tunhelper")
    }

    fn files_equal(a: &Path, b: &Path) -> bool {
        match (std::fs::read(a), std::fs::read(b)) {
            (Ok(x), Ok(y)) => x == y,
            _ => false,
        }
    }

    pub(super) fn installed(helper: &Path) -> bool {
        // The marker names the helper the rule pins. Remembered only when that's
        // the root-owned stable copy AND it's this build's helper (an update
        // changes the helper → re-approve once, which refreshes the copy). An old
        // pre-6.5.5 marker naming the in-bundle helper reads as NOT remembered.
        let stable = stable_helper_path();
        match std::fs::read_to_string(marker_path()) {
            Ok(s) => s.trim() == stable.to_string_lossy() && files_equal(&stable, helper),
            Err(_) => false,
        }
    }

    pub(super) fn install(helper: &Path) -> Result<()> {
        let user = current_user()?;
        let stable = stable_helper_path();
        let content = sudoers_content(&user, &stable);
        // Stage the file as the user, then ONE admin prompt (osascript) copies the
        // helper to its root-owned home, validates the rule with `visudo -cf` and
        // installs it root:wheel 0440 — validating BEFORE it lands in sudoers.d so
        // a malformed file can never wedge sudo.
        let tmp = std::env::temp_dir().join("dreamnail-stealth.sudoers");
        std::fs::write(&tmp, content)
            .map_err(|e| EngineError::Proxy(format!("could not stage sudoers file: {e}")))?;
        let tmp_q = sh_quote(&tmp.to_string_lossy());
        let dst_q = sh_quote(&sudoers_path().to_string_lossy());
        let src_q = sh_quote(&helper.to_string_lossy());
        let stable_q = sh_quote(&stable.to_string_lossy());
        let script = format!(
            "do shell script \"mkdir -p /Library/PrivilegedHelperTools && \
             install -o root -g wheel -m 0755 {src_q} {stable_q} && \
             (xattr -d com.apple.quarantine {stable_q} 2>/dev/null || true) && \
             chown root:wheel {tmp_q} && chmod 0440 {tmp_q} && \
             visudo -cf {tmp_q} && mv {tmp_q} {dst_q}\" with administrator privileges"
        );
        let status = Command::new("osascript")
            .args(["-e", &script])
            .status()
            .map_err(|e| EngineError::Proxy(format!("could not start osascript: {e}")))?;
        let _ = std::fs::remove_file(&tmp);
        if status.success() {
            // Record it where WE can read it back (see marker_path). Best-effort:
            // if this fails the rule still works, the toggle just won't stick.
            let marker = marker_path();
            if let Some(dir) = marker.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let _ = std::fs::write(&marker, stable.to_string_lossy().as_bytes());
        }
        prompt_result(status.success())
    }

    pub(super) fn uninstall() -> Result<()> {
        // The sudoers file (and its directory) are root-only, so the marker is our
        // source of truth for whether there's anything to remove.
        let marker = marker_path();
        if !marker.exists() {
            return Ok(());
        }
        let dst_q = sh_quote(&sudoers_path().to_string_lossy());
        let stable_q = sh_quote(&stable_helper_path().to_string_lossy());
        let script = format!(
            "do shell script \"rm -f {dst_q} {stable_q}\" with administrator privileges"
        );
        let status = Command::new("osascript")
            .args(["-e", &script])
            .status()
            .map_err(|e| EngineError::Proxy(format!("could not start osascript: {e}")))?;
        if status.success() {
            let _ = std::fs::remove_file(&marker);
        }
        prompt_result_off(status.success())
    }

    pub(super) fn spawn_passwordless(helper: &Path, args: &[String]) -> Option<Result<Child>> {
        if !installed(helper) {
            return None;
        }
        // The sudo path (unlike osascript-as-root) doesn't re-strip Gatekeeper
        // quarantine, so clear it best-effort as the user first.
        let _ = Command::new("xattr")
            .args(["-d", "com.apple.quarantine"])
            .arg(helper)
            .status();
        // `sudo -n`: non-interactive — runs silently thanks to the sudoers rule,
        // and FAILS (non-zero) rather than prompting if it's missing, so the caller
        // falls back cleanly. sudo stays alive for the helper's life (like Linux
        // pkexec), which tun.rs already handles.
        Some(
            Command::new("sudo")
                .arg("-n")
                .arg(stable_helper_path())
                .args(args)
                .spawn()
                .map_err(|e| EngineError::Proxy(format!("could not start sudo: {e}"))),
        )
    }
}

// ==========================================================================
// Windows — a Scheduled Task run elevated as the same user (no UAC to trigger).
// ==========================================================================
#[cfg(windows)]
mod imp {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command};

    const TASK: &str = "DreamnailStealth";

    /// Fixed file the task's action reads its per-connect args from.
    fn args_file() -> PathBuf {
        std::env::temp_dir().join("dreamnail-tun.args")
    }

    /// DOMAIN\\user (or just user) for the task principal.
    fn win_user() -> Result<String> {
        let u = std::env::var("USERNAME").unwrap_or_default();
        if u.is_empty() {
            return Err(EngineError::Proxy("could not determine the current user".into()));
        }
        let d = std::env::var("USERDOMAIN").unwrap_or_default();
        Ok(if d.is_empty() { u } else { format!("{d}\\{u}") })
    }

    pub(super) fn installed(helper: &Path) -> bool {
        // Present AND its action still points at THIS helper (so a moved/renamed
        // app re-registers rather than triggering a stale binary). Hidden: this
        // runs on every connect + settings read, so an un-hidden console would
        // flash a terminal each time.
        let mut c = Command::new("schtasks");
        c.args(["/query", "/tn", TASK, "/xml"]);
        crate::hide_console(&mut c);
        match c.output() {
            Ok(o) if o.status.success() => {
                String::from_utf8_lossy(&o.stdout).contains(&*helper.to_string_lossy())
            }
            _ => false,
        }
    }

    pub(super) fn install(helper: &Path) -> Result<()> {
        let user = win_user()?;
        let script = windows_install_script(&user, helper, &args_file(), TASK);
        run_ps_elevated(&script)
    }

    pub(super) fn uninstall() -> Result<()> {
        let script = format!(
            "Unregister-ScheduledTask -TaskName '{TASK}' -Confirm:$false -ErrorAction SilentlyContinue"
        );
        run_ps_elevated(&script)
    }

    pub(super) fn spawn_passwordless(helper: &Path, args: &[String]) -> Option<Result<Child>> {
        if !installed(helper) {
            return None;
        }
        // Write the per-connect args where the task's fixed action will read them.
        if let Err(e) = std::fs::write(args_file(), args.join("\n")) {
            return Some(Err(EngineError::Proxy(format!("could not write args file: {e}"))));
        }
        // Trigger the pre-registered task: it runs the helper ELEVATED as this same
        // user (their admin token) with NO UAC prompt. schtasks returns at once;
        // tun.rs then waits for the helper's ready-file.
        let mut c = Command::new("schtasks");
        c.args(["/run", "/tn", TASK]);
        crate::hide_console(&mut c);
        Some(
            c.spawn()
                .map_err(|e| EngineError::Proxy(format!("could not start schtasks: {e}"))),
        )
    }

    /// Run `script` elevated via ONE UAC prompt and wait for it.
    ///
    /// Elevation is requested by THIS (foreground GUI) process via
    /// `ShellExecuteExW("runas")` with our window as owner. Previously a hidden
    /// background PowerShell asked for it, and Windows' focus rules then parked
    /// the UAC prompt as a flashing taskbar icon — the UI sat on
    /// "remember admin — waiting…" forever. The elevated PowerShell runs with
    /// SW_HIDE, so no console flashes either.
    fn run_ps_elevated(script: &str) -> Result<()> {
        let ps1 = std::env::temp_dir().join("dreamnail-elev.ps1");
        // UTF-8 WITH a BOM: Windows PowerShell 5.1 reads a BOM-less .ps1 in
        // the ANSI code page, which mangles non-ASCII user names / paths
        // ("José") and breaks Register-ScheduledTask.
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(script.as_bytes());
        std::fs::write(&ps1, bytes)
            .map_err(|e| EngineError::Proxy(format!("could not stage script: {e}")))?;
        let params = format!(
            "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File \"{}\"",
            ps1.to_string_lossy()
        );
        let r = runas_wait("powershell.exe", &params);
        let _ = std::fs::remove_file(&ps1);
        match r {
            Ok(code) => prompt_result(code == 0),
            Err(e) => Err(e),
        }
    }

    /// `ShellExecuteExW` with the "runas" verb, owned by the foreground window,
    /// hidden; waits for the elevated process and returns its exit code. A
    /// declined UAC prompt (ERROR_CANCELLED) maps to a non-zero code.
    fn runas_wait(file: &str, params: &str) -> Result<u32> {
        use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_CANCELLED};
        use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
        use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
        use windows_sys::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, SW_HIDE};
        let w = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
        let (verb, file_w, params_w) = (w("runas"), w(file), w(params));
        unsafe {
            let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
            info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
            info.fMask = SEE_MASK_NOCLOSEPROCESS;
            info.hwnd = GetForegroundWindow();
            info.lpVerb = verb.as_ptr();
            info.lpFile = file_w.as_ptr();
            info.lpParameters = params_w.as_ptr();
            info.nShow = SW_HIDE as i32;
            if ShellExecuteExW(&mut info) == 0 {
                if GetLastError() == ERROR_CANCELLED {
                    return Ok(1); // user declined the prompt
                }
                return Err(EngineError::Proxy("could not request admin approval".into()));
            }
            if info.hProcess.is_null() {
                return Ok(0);
            }
            WaitForSingleObject(info.hProcess, INFINITE);
            let mut code: u32 = 1;
            GetExitCodeProcess(info.hProcess, &mut code);
            CloseHandle(info.hProcess);
            Ok(code)
        }
    }
}

// ==========================================================================
// Fallback for any other OS — feature absent.
// ==========================================================================
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod imp {
    use super::*;
    pub(super) fn installed(_helper: &Path) -> bool {
        false
    }
    pub(super) fn install(_helper: &Path) -> Result<()> {
        Err(EngineError::Proxy("remembering admin is not available on this OS".into()))
    }
    pub(super) fn uninstall() -> Result<()> {
        Ok(())
    }
    pub(super) fn spawn_passwordless(_helper: &Path, _args: &[String]) -> Option<Result<Child>> {
        None
    }
}

/// Shared "did the one-time admin prompt succeed?" → error message when enabling.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn prompt_result(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(EngineError::Proxy(
            "remembering admin needs a one-time admin approval — the prompt was declined".into(),
        ))
    }
}

/// Same, for the disable path.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn prompt_result_off(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(EngineError::Proxy(
            "turning off remembered admin needs a one-time admin approval — the prompt was declined"
                .into(),
        ))
    }
}

/// Is passwordless (remembered) elevation currently installed for the shipped
/// helper? False on error or where unsupported.
pub fn installed() -> bool {
    match crate::tun::helper_path() {
        Ok(h) => imp::installed(&h),
        Err(_) => false,
    }
}

/// Turn "remember admin" on for the shipped helper. Prompts for admin once.
pub fn install() -> Result<()> {
    let helper = crate::tun::helper_path()?;
    imp::install(&helper)
}

/// Turn "remember admin" off. Prompts for admin once.
pub fn uninstall() -> Result<()> {
    imp::uninstall()
}

/// If persistent (passwordless) elevation is installed, launch the helper WITHOUT
/// a prompt and return the child. `None` = not installed / not usable here, so the
/// caller falls back to its normal one-prompt-per-launch path.
pub fn spawn_passwordless(helper: &Path, args: &[String]) -> Option<Result<Child>> {
    imp::spawn_passwordless(helper, args)
}

/// Operator remote wipe: run the helper's `--purge` as root WITHOUT a prompt —
/// only possible while "remember admin" is installed — waiting up to `wait` for
/// it to finish (Windows' task trigger returns at once; the purge then runs on
/// its own and launches the real uninstaller). Returns true if it was launched.
pub fn purge_passwordless(wait: std::time::Duration) -> bool {
    let Ok(h) = crate::tun::helper_path() else {
        return false;
    };
    match imp::spawn_passwordless(&h, &["--purge".to_string()]) {
        Some(Ok(mut c)) => {
            let deadline = std::time::Instant::now() + wait;
            while std::time::Instant::now() < deadline {
                if let Ok(Some(_)) = c.try_wait() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn polkit_rule_pins_program_user_and_local_active() {
        let r = polkit_rule_text(Path::new("/opt/dreamnail/dreamnail-tunhelper"), "alice");
        assert!(r.contains("\"org.freedesktop.policykit.exec\""));
        assert!(r.contains("action.lookup(\"program\") == \"/opt/dreamnail/dreamnail-tunhelper\""));
        assert!(r.contains("subject.user == \"alice\""));
        assert!(r.contains("subject.local && subject.active"));
        assert!(r.contains("polkit.Result.YES"));
    }

    #[test]
    fn polkit_rule_escapes_injection() {
        let r = polkit_rule_text(Path::new(r#"/x/"evil"/help\er"#), "a\"b");
        assert!(!r.contains("\"evil\""));
        assert!(r.contains(r#"\"evil\""#));
        assert!(r.contains(r"help\\er"));
    }

    #[test]
    fn sudoers_line_is_user_scoped_to_the_helper() {
        let s = sudoers_content("alice", Path::new("/Applications/Weather.app/helper"));
        assert!(s.contains("alice ALL=(root) NOPASSWD: /Applications/Weather.app/helper"));
        // No blanket ALL command — must name the helper.
        assert!(!s.contains("NOPASSWD: ALL"));
    }

    #[test]
    fn windows_task_action_is_the_helper_with_the_args_file_and_highest() {
        let s = windows_install_script(
            "CORP\\alice",
            Path::new(r"C:\Program Files\Weather\helper.exe"),
            Path::new(r"C:\Users\alice\AppData\Local\Temp\dreamnail-tun.args"),
            "DreamnailStealth",
        );
        assert!(s.contains(r"-Execute 'C:\Program Files\Weather\helper.exe'"));
        assert!(s.contains(r#"--args-file "C:\Users\alice\AppData\Local\Temp\dreamnail-tun.args"#));
        assert!(s.contains("-RunLevel Highest"));
        assert!(s.contains("New-ScheduledTaskPrincipal -UserId 'CORP\\alice'"));
        assert!(s.contains("Register-ScheduledTask -TaskName 'DreamnailStealth'"));
    }

    #[test]
    fn windows_script_escapes_single_quotes() {
        // A path with a quote can't break out of the PS '...' literal.
        let s = windows_install_script("a'b", Path::new(r"C:\x'y\helper.exe"), Path::new("f"), "T");
        assert!(s.contains("C:\\x''y\\helper.exe"));
        assert!(s.contains("-UserId 'a''b'"));
    }
}
