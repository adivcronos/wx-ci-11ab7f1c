//! True OTA (6.5.6): install a downloaded, verified update SILENTLY and relaunch
//! — instead of opening an installer wizard / showing an "update available"
//! banner and waiting for the user.
//!
//! Two halves:
//! * [`silent_apply`] — runs in the app (as the user). Picks the quietest path
//!   this install allows:
//!     - Linux AppImage / extracted AppDir: swap the file / folder in place (the
//!       user owns it — no admin at all), relaunch.
//!     - Linux .deb, macOS in /Applications: install through the root helper
//!       passwordlessly when "remember admin" is on.
//!     - macOS bundle the user owns: replace it as the user.
//!     - Windows: the Inno installer in /SILENT mode — via the elevated helper
//!       (no UAC) when "remember admin" is on, else one UAC consent.
//!     - anything else: [`Outcome::NeedsUser`] → the normal update prompt.
//! * [`root_apply`] — the helper's `--apply-update <manifest> <package>` mode,
//!   running as root/admin. It trusts NOTHING from the caller: the manifest's
//!   operator signature is checked unconditionally (no env escape hatch — on
//!   Windows the helper's environment is user-influenced), the version must be
//!   strictly newer than this build (no downgrade to an older, weaker build),
//!   and the package is copied into a root-only directory FIRST and its sha256
//!   checked on that copy (no swap-after-check), against a signed entry with the
//!   same file type. Only then is it installed.

use std::path::{Path, PathBuf};
#[allow(unused_imports)]
use std::process::{Command, Stdio};

use crate::updater::{is_newer, sha256_file, verify_manifest_sig, UsbBuild};

/// What happened to a silent install attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Installed; a relaunch of the new build is scheduled. The caller should
    /// quit now so it can take over.
    Restart,
    /// Handed to an installer that will close and relaunch the app itself
    /// (Windows). The caller should keep running until it's closed.
    Handoff,
    /// Can't be done silently here (no admin grant, read-only install…). The
    /// caller falls back to the normal "update available" prompt.
    NeedsUser(String),
}

// --------------------------------------------------------------------------
// Root-side verification (pure; unit-tested)
// --------------------------------------------------------------------------

/// Check a manifest + package hash for a privileged install. Returns the
/// manifest version on success. `ext` is the package's file extension
/// (`deb`/`AppImage`/`exe`/`dmg`); `current` the running build's version.
pub fn verify_for_root(text: &str, sha: &str, ext: &str, current: &str) -> Result<String, String> {
    if !verify_manifest_sig(text) {
        return Err("manifest signature missing or invalid".into());
    }
    let data: serde_json::Value =
        serde_json::from_str(text).map_err(|_| "manifest is not JSON".to_string())?;
    let version = data
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or("manifest has no version")?
        .to_string();
    if !is_newer(&version, current) {
        return Err(format!("v{version} is not newer than v{current} — refusing"));
    }
    let suffix = format!(".{}", ext.to_ascii_lowercase());
    let platforms = data
        .get("platforms")
        .and_then(|p| p.as_object())
        .ok_or("manifest has no platforms")?;
    let ok = platforms.values().any(|e| {
        let file = e.get("file").and_then(|f| f.as_str()).unwrap_or("");
        let want = e.get("sha256").and_then(|h| h.as_str()).unwrap_or("");
        !want.is_empty()
            && want.eq_ignore_ascii_case(sha)
            && file.to_ascii_lowercase().ends_with(&suffix)
    });
    if ok {
        Ok(version)
    } else {
        Err("package hash matches no signed entry of that type".into())
    }
}

fn ext_of(p: &Path) -> String {
    p.extension().map(|e| e.to_string_lossy().into_owned()).unwrap_or_default()
}

// --------------------------------------------------------------------------
// Root side: helper `--apply-update <manifest> <package>`
// --------------------------------------------------------------------------

/// Root-only parent for staging the verified copy. Its own parent must be
/// writable by root only (on macOS /Library/Caches is admin-group writable, so
/// a user could swap the folder mid-install — /private/var/db is root-only).
fn root_stage_dir() -> PathBuf {
    #[cfg(target_os = "linux")]
    return PathBuf::from("/var/cache/dreamnail-update");
    #[cfg(target_os = "macos")]
    return PathBuf::from("/private/var/db/dreamnail-update");
    #[cfg(windows)]
    return std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join("update")))
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData\Dreamnail\update"));
    #[allow(unreachable_code)]
    PathBuf::from("/nonexistent")
}

fn fresh_root_dir(dir: &Path) -> std::io::Result<()> {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// A brand-new staging folder for THIS run only. Every run used to wipe and
/// reuse one fixed folder, so a second (attacker-started) `--apply-update`
/// could swap the package after this run had hashed it but before it was
/// installed. Now: the shared parent is never wiped, each run creates its own
/// child with `create_dir` (fails if it already exists), and leftovers from
/// runs over an hour old are tidied.
fn new_run_dir() -> std::io::Result<PathBuf> {
    let base = root_stage_dir();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // Never follow a planted symlink / foreign-owned folder.
        if let Ok(m) = std::fs::symlink_metadata(&base) {
            if !m.is_dir() || m.uid() != 0 {
                let _ = std::fs::remove_file(&base);
                let _ = std::fs::remove_dir_all(&base);
            }
        }
    }
    std::fs::create_dir_all(&base)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700))?;
    }
    if let Ok(rd) = std::fs::read_dir(&base) {
        for e in rd.flatten() {
            let old = e
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .map(|d| d.as_secs() > 3600)
                .unwrap_or(false);
            if old {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = base.join(format!("run-{}-{nanos}", std::process::id()));
    std::fs::create_dir(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

/// The helper's `--apply-update` body. Returns a process exit code (0 = done).
pub fn root_apply(manifest: &Path, package: &Path) -> i32 {
    let text = match std::fs::read_to_string(manifest) {
        Ok(t) => t,
        Err(e) => {
            log::error!("apply-update: cannot read manifest: {e}");
            return 2;
        }
    };
    let ext = ext_of(package);
    let stage = match new_run_dir() {
        Ok(d) => d,
        Err(e) => {
            log::error!("apply-update: cannot prepare {}: {e}", root_stage_dir().display());
            return 2;
        }
    };
    let staged = stage.join(format!("update.{ext}"));
    if let Err(e) = std::fs::copy(package, &staged) {
        log::error!("apply-update: cannot copy package: {e}");
        return 2;
    }
    let Some(sha) = sha256_file(&staged) else {
        return 2;
    };
    let version = match verify_for_root(&text, &sha, &ext, crate::netcfg::APP_VERSION) {
        Ok(v) => v,
        Err(why) => {
            log::error!("apply-update: REFUSED — {why}");
            let _ = std::fs::remove_dir_all(&stage);
            return 3;
        }
    };
    log::info!("apply-update: verified v{version} ({ext}), installing");
    let r = install_staged(&staged, &ext, &stage);
    match r {
        Ok(()) => {
            log::info!("apply-update: v{version} installed");
            #[cfg(not(windows))]
            let _ = std::fs::remove_dir_all(&stage);
            0
        }
        Err(e) => {
            log::error!("apply-update: install failed: {e}");
            let _ = std::fs::remove_dir_all(&stage);
            4
        }
    }
}

#[allow(unused_variables)]
fn install_staged(staged: &Path, ext: &str, stage: &Path) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        match ext {
            "deb" => {
                let ok = Command::new("apt-get")
                    .args(["install", "-y", "--no-install-recommends"])
                    .arg(staged)
                    .env("DEBIAN_FRONTEND", "noninteractive")
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false)
                    || Command::new("dpkg")
                        .arg("-i")
                        .arg(staged)
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false);
                return if ok { Ok(()) } else { Err("apt-get/dpkg failed".into()) };
            }
            "AppImage" | "appimage" => {
                // The app swaps the AppImage itself (the user owns it); our job is
                // to refresh the root-owned helper copy the passwordless rule pins
                // (crate::elevation), from THIS verified package.
                let _ = std::fs::set_permissions(staged, std::fs::Permissions::from_mode(0o755));
                let x = stage.join("x");
                fresh_root_dir(&x).map_err(|e| e.to_string())?;
                let ok = Command::new(staged)
                    .args(["--appimage-extract", "usr/bin/dreamnail-tunhelper"])
                    .current_dir(&x)
                    .stdout(Stdio::null())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
                let fresh = x.join("squashfs-root/usr/bin/dreamnail-tunhelper");
                if !ok || !fresh.exists() {
                    return Err("could not extract the helper from the AppImage".into());
                }
                let dst = Path::new("/usr/local/lib/dreamnail/dreamnail-tunhelper");
                std::fs::create_dir_all("/usr/local/lib/dreamnail").map_err(|e| e.to_string())?;
                let tmp = dst.with_extension("new");
                std::fs::copy(&fresh, &tmp).map_err(|e| e.to_string())?;
                std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
                    .map_err(|e| e.to_string())?;
                std::fs::rename(&tmp, dst).map_err(|e| e.to_string())?;
                let _ = std::fs::remove_dir_all(stage);
                return Ok(());
            }
            _ => return Err(format!("unsupported package type .{ext}")),
        }
    }
    #[cfg(target_os = "macos")]
    {
        if !ext.eq_ignore_ascii_case("dmg") {
            return Err(format!("unsupported package type .{ext}"));
        }
        // Root only ever replaces the standard location — never a caller-chosen
        // path.
        let r = mac_replace_bundle(staged, Path::new("/Applications/Weather.app"), Some(stage));
        let _ = std::fs::remove_dir_all(stage);
        return r;
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        if !ext.eq_ignore_ascii_case("exe") {
            return Err(format!("unsupported package type .{ext}"));
        }
        // Detached: the installer stops this helper (and the app) as part of the
        // upgrade, then relaunches the app (/RELAUNCH, see win_installer.iss).
        return Command::new(staged)
            .args(["/SILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/RELAUNCH"])
            .creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW)
            .spawn()
            .map(|_| ())
            .map_err(|e| e.to_string());
    }
    #[allow(unreachable_code)]
    Err("unsupported OS".into())
}

/// Replace a macOS app bundle with the one inside `dmg`. `root_stage` = Some
/// when running as root (mount there, keep the old bundle's owner, refresh the
/// root-owned helper copy); None when running as the user.
#[cfg(target_os = "macos")]
pub(crate) fn mac_replace_bundle(dmg: &Path, dst: &Path, root_stage: Option<&Path>) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let run = |c: &mut Command| c.stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false);
    if !dst.join("Contents/MacOS").is_dir() {
        return Err(format!("{} is not an installed app", dst.display()));
    }
    let mnt = match root_stage {
        Some(s) => s.join("mnt"),
        None => std::env::temp_dir().join(format!("dn-ota-mnt-{}", std::process::id())),
    };
    let _ = std::fs::create_dir_all(&mnt);
    if !run(Command::new("hdiutil").args(["attach", "-nobrowse", "-readonly", "-noautoopen", "-mountpoint"]).arg(&mnt).arg(dmg)) {
        return Err("could not mount the update".into());
    }
    let detach = |m: &Path| {
        let _ = Command::new("hdiutil").args(["detach", "-force"]).arg(m).stdout(Stdio::null()).stderr(Stdio::null()).status();
    };
    let src = std::fs::read_dir(&mnt)
        .ok()
        .and_then(|rd| rd.flatten().map(|e| e.path()).find(|p| p.extension().map(|x| x == "app").unwrap_or(false)));
    let Some(src) = src else {
        detach(&mnt);
        return Err("no app inside the update".into());
    };
    let parent = dst.parent().unwrap_or(Path::new("/Applications"));
    let name = dst.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "Weather.app".into());
    let new = parent.join(format!(".{name}.new"));
    let old = parent.join(format!(".{name}.old"));
    let _ = std::fs::remove_dir_all(&new);
    let _ = std::fs::remove_dir_all(&old);
    if !run(Command::new("ditto").arg(&src).arg(&new)) {
        detach(&mnt);
        let _ = std::fs::remove_dir_all(&new);
        return Err("could not copy the new app".into());
    }
    // Root: refresh the root-owned helper copy the passwordless sudoers rule
    // pins straight from the READ-ONLY mounted image, before the new bundle is
    // handed to the user (a user-owned bundle could be swapped mid-way).
    let helper_ok = match root_stage {
        Some(_) => run(Command::new("install")
            .args(["-o", "root", "-g", "wheel", "-m", "0755"])
            .arg(src.join("Contents/MacOS/dreamnail-tunhelper"))
            .arg("/Library/PrivilegedHelperTools/dreamnail-tunhelper")),
        None => true,
    };
    detach(&mnt);
    if !helper_ok {
        log::warn!("apply-update: could not refresh the root helper copy");
    }
    if root_stage.is_some() {
        // Keep the bundle owned by whoever owned it (the user), so later
        // updates/uninstalls as the user still work.
        if let Ok(m) = std::fs::metadata(dst) {
            let _ = run(Command::new("chown").arg("-R").arg(format!("{}:{}", m.uid(), m.gid())).arg(&new));
        }
    }
    let _ = run(Command::new("xattr").args(["-dr", "com.apple.quarantine"]).arg(&new));
    if std::fs::rename(dst, &old).is_err() {
        let _ = std::fs::remove_dir_all(&new);
        return Err("could not move the old app aside".into());
    }
    if std::fs::rename(&new, dst).is_err() {
        let _ = std::fs::rename(&old, dst); // put the old one back
        return Err("could not move the new app into place".into());
    }
    let _ = std::fs::remove_dir_all(&old);
    Ok(())
}

// --------------------------------------------------------------------------
// App side
// --------------------------------------------------------------------------

/// Write the signature-verified manifest for the root helper to re-verify.
#[allow(dead_code)]
fn manifest_file() -> Option<PathBuf> {
    let text = crate::updater::LAST_MANIFEST.lock().ok()?.clone()?;
    let p = std::env::temp_dir().join(format!("dreamnail-ota-manifest-{}.json", std::process::id()));
    std::fs::write(&p, text).ok()?;
    Some(p)
}

/// Run the root helper's `--apply-update` passwordlessly and wait for it.
/// None = "remember admin" isn't on (or no helper), so no silent root path.
#[allow(dead_code)]
fn root_helper_apply(pkg: &Path) -> Option<bool> {
    if !crate::elevation::installed() {
        return None;
    }
    let helper = crate::tun::helper_path().ok()?;
    let m = manifest_file()?;
    let args = vec![
        "--apply-update".to_string(),
        m.to_string_lossy().into_owned(),
        pkg.to_string_lossy().into_owned(),
    ];
    let mut child = crate::elevation::spawn_passwordless(&helper, &args)?.ok()?;
    if cfg!(windows) {
        // The task trigger returns at once; the helper hands off to the
        // installer, which closes + relaunches us.
        return Some(true);
    }
    // Bounded: an old helper copy that doesn't know --apply-update, or a stuck
    // apt/dpkg lock, must not hang the update thread forever.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15 * 60);
    let ok = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s.success(),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(500))
            }
            _ => {
                let _ = child.kill();
                break false;
            }
        }
    };
    let _ = std::fs::remove_file(&m);
    Some(ok)
}

/// Start `program args` ~3s after we exit, fully detached, so the new build
/// doesn't collide with this instance's single-instance lock.
#[cfg(unix)]
#[allow(dead_code)]
fn relaunch_later(program: &Path, args: &[&str]) -> bool {
    use std::os::unix::process::CommandExt;
    // Wait (max ~30s) until this process has really exited, then 1s more:
    // macOS `open` would otherwise just re-focus the still-quitting old copy,
    // and the single-instance lock would make a too-early start bail out.
    Command::new("/bin/sh")
        .arg("-c")
        .arg(format!(
            "i=0; while kill -0 {pid} 2>/dev/null && [ $i -lt 60 ]; do sleep 0.5; i=$((i+1)); done; sleep 1; exec \"$@\"",
            pid = std::process::id()
        ))
        .arg("sh")
        .arg(program)
        .args(args)
        // A relaunched AppImage/AppRun sets these afresh; never inherit ours.
        .env_remove("APPIMAGE")
        .env_remove("APPDIR")
        .env_remove("ARGV0")
        .env_remove("OWD")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .is_ok()
}

/// .deb path only: detached `sh` that outlives us (own process group, name
/// "sh" so the package's `pkill -x dreamnail_ui` can't hit it). Waits up to
/// 10 min for apt/dpkg/the helper to finish ("[-]-apply" so the pattern can't
/// match this watcher's own command line), then up to 30s for the old app to
/// be gone, then starts the newly installed app.
#[cfg(target_os = "linux")]
fn deb_relaunch_watcher() {
    use std::os::unix::process::CommandExt;
    let script = "sleep 4; i=0; \
        while [ $i -lt 600 ] && { pgrep -x apt-get || pgrep -x dpkg || pgrep -f '[-]-apply-update'; } >/dev/null 2>&1; \
        do sleep 1; i=$((i+1)); done; \
        j=0; while pgrep -x dreamnail_ui >/dev/null 2>&1 && [ $j -lt 30 ]; do sleep 1; j=$((j+1)); done; \
        sleep 1; [ -x /opt/weather/dreamnail_ui ] && exec /opt/weather/dreamnail_ui";
    let _ = Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn();
}

/// Could `silent_apply` finish without the user on this install? Checked
/// BEFORE downloading so a build that would only end in "needs you" isn't
/// re-downloaded (through the VPN, on the customer's data) every cycle.
pub fn silent_possible() -> bool {
    #[cfg(target_os = "linux")]
    {
        if crate::updater::platform_key() != "linux_appimage" {
            return crate::elevation::installed();
        }
    }
    true
}

/// Install `b` silently. See the module docs for what each platform does.
pub fn silent_apply(b: &UsbBuild) -> Outcome {
    #[cfg(windows)]
    {
        // Same shape as root_apply's installer launch, minus elevation: Inno
        // asks for ONE UAC consent, then installs silently, closes the app and
        // relaunches it.
        if let Some(true) = root_helper_apply(&b.package) {
            return Outcome::Handoff;
        }
        return match Command::new(&b.package)
            .args(["/SILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/RELAUNCH"])
            .spawn()
        {
            Ok(_) => Outcome::Handoff,
            Err(e) => Outcome::NeedsUser(format!("installer did not start: {e}")),
        };
    }
    #[cfg(target_os = "macos")]
    {
        let Some(bundle) = std::env::current_exe()
            .ok()
            .and_then(|p| p.ancestors().nth(3).map(Path::to_path_buf))
            .filter(|a| a.extension().map(|e| e == "app").unwrap_or(false))
        else {
            return Outcome::NeedsUser("not running from an app bundle".into());
        };
        let std_loc = bundle == Path::new("/Applications/Weather.app");
        let done = if std_loc && root_helper_apply(&b.package) == Some(true) {
            true
        } else {
            // As the user — works whenever the user owns the bundle (the normal
            // drag-install by an admin account).
            match mac_replace_bundle(&b.package, &bundle, None) {
                Ok(()) => true,
                Err(e) => return Outcome::NeedsUser(e),
            }
        };
        if done && relaunch_later(Path::new("/usr/bin/open"), &[&bundle.to_string_lossy()]) {
            return Outcome::Restart;
        }
        return Outcome::NeedsUser("could not schedule the relaunch".into());
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        let pkg = &b.package;
        if crate::updater::platform_key() != "linux_appimage" {
            // .deb: needs root. Silent only with "remember admin".
            if !crate::elevation::installed() {
                return Outcome::NeedsUser("installing a .deb needs admin".into());
            }
            // The INSTALLED package's prerm (6.5.11 and older) kills every
            // dreamnail_ui during the upgrade — including us, while we wait on
            // the helper — so a relaunch scheduled afterwards never happens.
            // Start a detached watcher FIRST: it waits for the install to
            // finish and for no copy to be running, then starts the new build.
            deb_relaunch_watcher();
            return match root_helper_apply(pkg) {
                Some(true) => Outcome::Restart,
                Some(false) => Outcome::NeedsUser("the package install failed".into()),
                None => Outcome::NeedsUser("installing a .deb needs admin".into()),
            };
        }
        let _ = std::fs::set_permissions(pkg, std::fs::Permissions::from_mode(0o755));
        let target: PathBuf = if let Some(ai) = std::env::var_os("APPIMAGE").map(PathBuf::from) {
            // Swap the AppImage file in place (atomic rename; our running copy
            // keeps its old inode).
            let dir = ai.parent().unwrap_or(Path::new(".")).to_path_buf();
            let tmp = dir.join(".dreamnail-update.AppImage.tmp");
            if let Err(e) = std::fs::copy(pkg, &tmp)
                .and_then(|_| std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)))
                .and_then(|_| std::fs::rename(&tmp, &ai))
            {
                let _ = std::fs::remove_file(&tmp);
                return Outcome::NeedsUser(format!("could not replace the AppImage: {e}"));
            }
            ai
        } else if let Some(appdir) = std::env::var_os("APPDIR").map(PathBuf::from) {
            // Extracted AppDir: unpack the new AppImage beside it, swap folders.
            if !appdir.join("AppRun").exists() {
                return Outcome::NeedsUser("APPDIR has no AppRun".into());
            }
            let parent = appdir.parent().unwrap_or(Path::new(".")).to_path_buf();
            let work = parent.join(format!(".dn-update-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&work);
            if std::fs::create_dir_all(&work).is_err() {
                return Outcome::NeedsUser("cannot write next to the AppDir".into());
            }
            let ok = Command::new(pkg)
                .arg("--appimage-extract")
                .current_dir(&work)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            let fresh = work.join("squashfs-root");
            if !ok || !fresh.join("AppRun").exists() {
                let _ = std::fs::remove_dir_all(&work);
                return Outcome::NeedsUser("could not unpack the update".into());
            }
            let name = appdir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let old = parent.join(format!(".{name}.old-{}", std::process::id()));
            if std::fs::rename(&appdir, &old).is_err() {
                let _ = std::fs::remove_dir_all(&work);
                return Outcome::NeedsUser("could not move the old AppDir aside".into());
            }
            if std::fs::rename(&fresh, &appdir).is_err() {
                let _ = std::fs::rename(&old, &appdir);
                let _ = std::fs::remove_dir_all(&work);
                return Outcome::NeedsUser("could not move the new AppDir into place".into());
            }
            let _ = std::fs::remove_dir_all(&old);
            let _ = std::fs::remove_dir_all(&work);
            appdir.join("AppRun")
        } else {
            return Outcome::NeedsUser("not an AppImage install".into());
        };
        // Refresh the root-owned helper copy the passwordless rule pins, so
        // "remember admin" keeps working with no re-prompt after the update.
        let _ = root_helper_apply(pkg);
        if relaunch_later(&target, &[]) {
            return Outcome::Restart;
        }
        return Outcome::NeedsUser("could not schedule the relaunch".into());
    }
    #[allow(unreachable_code)]
    {
        let _ = b;
        Outcome::NeedsUser("unsupported OS".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The operator-signed interop vector from updater.rs's tests:
    // version 5.5.7, linux a.deb sha "aa", windows b.exe sha "bb".
    const GOOD: &str = r#"{"version":"5.5.7","base_url":"https://penguinwalker.dev/downloads/v4/","platforms":{"windows":{"file":"b.exe","sha256":"bb"},"linux":{"file":"a.deb","sha256":"aa"}},"sig":"54b3113be11a1274ef2df8eb1b7efee3e328ab5b3590edda450d5489c17f7ba103498d1548de781138f085dfd09e4cd7d2de8327842212a00ad3249a69175c0f"}"#;

    #[test]
    fn root_accepts_signed_newer_matching_package() {
        assert_eq!(verify_for_root(GOOD, "bb", "exe", "5.5.6").as_deref(), Ok("5.5.7"));
        assert_eq!(verify_for_root(GOOD, "AA", "deb", "5.4.0").as_deref(), Ok("5.5.7"));
    }

    #[test]
    fn root_refuses_downgrade_or_same_version() {
        assert!(verify_for_root(GOOD, "bb", "exe", "5.5.7").is_err());
        assert!(verify_for_root(GOOD, "bb", "exe", "6.0.0").is_err());
    }

    #[test]
    fn root_refuses_wrong_hash_or_type() {
        assert!(verify_for_root(GOOD, "cc", "exe", "5.5.6").is_err());
        // Right hash, wrong file type (the .deb's hash offered as an .exe).
        assert!(verify_for_root(GOOD, "aa", "exe", "5.5.6").is_err());
    }

    #[test]
    fn root_refuses_tampered_manifest() {
        let forged = GOOD.replace("\"bb\"", "\"dd\"");
        assert!(verify_for_root(&forged, "dd", "exe", "5.5.6").is_err());
        let unsigned = r#"{"version":"9.9.9","platforms":{"windows":{"file":"b.exe","sha256":"bb"}}}"#;
        assert!(verify_for_root(unsigned, "bb", "exe", "5.5.6").is_err());
    }
}
