//! Anonymous, opt-outable error telemetry.
//!
//! When a connection attempt fails, the app sends ONE tiny report to the download
//! host so the operator sees problems before customers complain. It is designed
//! to carry NOTHING that identifies a person:
//!
//!   * no username, no password, no email, no account id;
//!   * no IP address, no server address, no file paths;
//!   * no free-form error text (which could contain any of the above) — only a
//!     fixed category + a fixed coarse hint chosen from a closed list by the
//!     caller;
//!   * time is coarsened to the UTC hour, not a precise timestamp.
//!
//! The report is a handful of fixed, non-identifying fields sent as an HTTPS GET
//! query to `/ingest` on the download host (its Let's Encrypt cert is verified
//! normally — no cert-skipping). A GET is used so the server can record the line
//! with a plain nginx access-log rule that OMITS the client IP — no app, script,
//! or request-body handling on the server, and nothing personal in the query (by
//! construction: only version/os/arch and a fixed error category+hint). Delivery
//! is best-effort and fully fire-and-forget: it runs on its own thread, times out
//! fast, and swallows every error, so it can never slow down or break a connect.

use std::time::Duration;

use crate::netcfg::{API_HOST, APP_VERSION};

/// Set to false at runtime (once, at startup) to disable all reporting — wired to
/// the user-facing setting. Defaults to on.
static ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

pub fn set_enabled(on: bool) {
    ENABLED.store(on, std::sync::atomic::Ordering::SeqCst);
}

fn enabled() -> bool {
    // An env override lets tests / privacy-conscious users hard-disable it.
    if std::env::var("DREAMNAIL_NO_REPORTS").is_ok() {
        return false;
    }
    ENABLED.load(std::sync::atomic::Ordering::SeqCst)
}

/// A short random id so duplicate retries of the SAME failure can be collapsed by
/// the operator. Not derived from anything about the machine or user — it is
/// fresh per call, so it cannot identify or link reports across sessions.
fn nonce() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    // A cheap, dependency-free pseudo-random hex from the nanosecond clock. This
    // is an anti-duplicate tag, not a security value, so the clock is plenty.
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{:08x}", n)
}

/// UTC time coarsened to the hour ("2026-09-25T22"), so reports cluster by hour
/// without being a precise per-user timestamp. Computed without extra deps.
fn utc_hour() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // days since epoch → civil date (Howard Hinnant's algorithm).
    let days = (secs / 86_400) as i64;
    let hour = (secs % 86_400) / 3_600;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}T{:02}", y, m, d, hour)
}

/// Fire off one anonymous report for a failed connect. `category` and `hint` MUST
/// come from the caller's fixed lists (see the FFI's `report_hint`), never from
/// raw error text. Returns immediately; the send happens on a detached thread.
pub fn send_connect_failure(category: &'static str, hint: &'static str) {
    if !enabled() {
        return;
    }
    // All fields are from closed, non-identifying sets, so a plain query is safe.
    let query = format!(
        "kind=connect_fail&v={}&os={}&arch={}&cat={}&hint={}&t={}&id={}",
        APP_VERSION,
        std::env::consts::OS,
        std::env::consts::ARCH,
        category,
        hint,
        utc_hour(),
        nonce(),
    );
    std::thread::spawn(move || {
        // no_proxy: report directly, not through the (down) tunnel. Short timeout;
        // any failure is ignored — telemetry must never affect the app.
        let client = match reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(4))
            .no_proxy()
            .build()
        {
            Ok(c) => c,
            Err(_) => return,
        };
        let url = format!("https://{API_HOST}/ingest?{query}");
        let _ = client.get(url).send();
    });
}

/// Minimal JSON string encoder (the `json` reqwest feature isn't enabled here).
/// Mirrors the one in `entitlements` so credentials/diagnostics can't break the
/// body or smuggle control characters.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Send ONE authenticated, per-customer problem report to the server so the
/// operator sees it in the admin console.
///
/// Unlike [`send_connect_failure`], this is deliberately tied to the customer —
/// it authenticates with their own SSH login (the same oracle `/api/me` uses) so
/// the operator can see *which* customer hit *what*. It carries a diagnostics
/// bundle (`fields`, already assembled by the caller from the leak-test / engine
/// state — never raw error text) plus an optional typed `message`.
///
/// `leaktest`, when set, makes this run the one-click leak test on its own thread
/// and fold the results into the bundle, so the "Report a problem" button ships
/// real diagnostics without blocking the UI.
///
/// `manual` reports (the button) bypass the telemetry opt-out — the customer
/// explicitly asked to send. Automatic reports honour it. Best-effort: detached
/// thread, short timeout, every error swallowed — a report can never affect the
/// app. `host` is the server (its LE cert is verified normally); the call goes
/// `no_proxy` so it does not try to ride a tunnel that may be down.
pub fn send_report(
    user: &str,
    pass: &str,
    kind: &str,
    message: &str,
    fields: Vec<(String, String)>,
    leaktest: Option<crate::diag::Session>,
    manual: bool,
) {
    if !manual && !enabled() {
        return;
    }
    let (user, pass, kind, message) =
        (user.to_string(), pass.to_string(), kind.to_string(), message.to_string());
    std::thread::spawn(move || {
        let mut fields = fields;
        if let Some(sess) = leaktest {
            for c in crate::diag::run_all(sess) {
                fields.push((format!("chk_{}", c.key), format!("{}: {}", c.level.as_str(), c.detail)));
            }
        }
        let rest = report_rest(&kind, &message, &fields);
        // No login to authenticate with yet (never connected this run) → hold it
        // for the next successful connect instead of dropping it.
        if user.is_empty() || !deliver(&user, &pass, &rest) {
            outbox_save(&rest);
        }
    });
}

/// The report body minus the credentials: everything after `"password":…,`.
/// This is what the outbox stores, so a queued report never puts the
/// customer's password on disk — it's re-authenticated with the live login
/// when it's finally sent.
fn report_rest(kind: &str, message: &str, fields: &[(String, String)]) -> String {
    let mut extra = String::new();
    for (k, v) in fields {
        extra.push(',');
        extra.push_str(&json_string(k));
        extra.push(':');
        extra.push_str(&json_string(v));
    }
    format!(
        "\"kind\":{},\"message\":{},\"v\":{},\"os\":{},\"arch\":{},\"fields\":{{{}}}",
        json_string(kind),
        json_string(message),
        json_string(APP_VERSION),
        json_string(std::env::consts::OS),
        json_string(std::env::consts::ARCH),
        extra.trim_start_matches(','),
    )
}

/// POST one report. Tries the direct route first, then through the local tunnel
/// (a school filter that blocks the server directly still lets the tunnel
/// through). `true` only when the server accepted it (2xx).
fn deliver(user: &str, pass: &str, rest: &str) -> bool {
    let body = format!(
        "{{\"username\":{},\"password\":{},{}}}",
        json_string(user),
        json_string(pass),
        rest
    );
    let url = format!("https://{API_HOST}/api/report");
    let attempt = |via_tunnel: bool| -> Option<bool> {
        let mut b = reqwest::blocking::Client::builder().timeout(Duration::from_secs(8));
        b = if via_tunnel {
            b.proxy(reqwest::Proxy::all(crate::updater::tunnel_proxy_url()).ok()?)
        } else {
            b.no_proxy()
        };
        let r = b
            .build()
            .ok()?
            .post(&url)
            .header("Content-Type", "application/json")
            .body(body.clone())
            .send()
            .ok()?;
        Some(r.status().is_success())
    };
    attempt(false) == Some(true) || attempt(true) == Some(true)
}

// ---- outbox: reports that couldn't be sent yet ------------------------------
// Each is one small file (credential-free body, see `report_rest`) in
// `<data dir>/outbox/`. Flushed on the next successful connect. Bounded: at
// most OUTBOX_MAX files (oldest dropped), and anything older than two weeks is
// discarded rather than sent stale.
const OUTBOX_MAX: usize = 20;
const OUTBOX_TTL_SECS: u64 = 14 * 24 * 3600;

fn outbox_dir() -> std::path::PathBuf {
    crate::xray::data_dir().join("outbox")
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Queued reports, oldest first: (path, saved-at secs).
fn outbox_list() -> Vec<(std::path::PathBuf, u64)> {
    outbox_list_in(&outbox_dir())
}

fn outbox_list_in(dir: &std::path::Path) -> Vec<(std::path::PathBuf, u64)> {
    let mut v: Vec<_> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter_map(|e| {
                    let p = e.path();
                    let ts = p.file_stem()?.to_str()?.split('-').next()?.parse::<u64>().ok()?;
                    (p.extension()? == "rep").then_some((p, ts))
                })
                .collect()
        })
        .unwrap_or_default();
    v.sort_by_key(|(_, t)| *t);
    v
}

fn outbox_save(rest: &str) {
    outbox_save_in(&outbox_dir(), rest);
}

// Takes the folder explicitly so tests don't have to change the process-wide
// data-dir variable (which raced other tests reading it in parallel).
fn outbox_save_in(dir: &std::path::Path, rest: &str) {
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = dir.join(format!("{}-{}{:04}.rep", now_secs(), nonce(), seq % 10_000));
    let _ = std::fs::write(&path, rest);
    let all = outbox_list_in(dir);
    if all.len() > OUTBOX_MAX {
        for (p, _) in &all[..all.len() - OUTBOX_MAX] {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// How many reports are waiting to be sent (for the UI / tests).
pub fn outbox_len() -> usize {
    outbox_list().len()
}

/// Send every queued report with the customer's live login. Called right after
/// a successful connect (the tunnel is up, so even a blocked network works).
/// Detached thread; a report that still fails stays queued for next time.
pub fn flush_outbox(user: &str, pass: &str) {
    if user.is_empty() || outbox_list().is_empty() {
        return;
    }
    let (user, pass) = (user.to_string(), pass.to_string());
    std::thread::spawn(move || {
        let now = now_secs();
        for (p, ts) in outbox_list() {
            if now.saturating_sub(ts) > OUTBOX_TTL_SECS {
                let _ = std::fs::remove_file(&p);
                continue;
            }
            let Ok(rest) = std::fs::read_to_string(&p) else {
                let _ = std::fs::remove_file(&p);
                continue;
            };
            if deliver(&user, &pass, &rest) {
                let _ = std::fs::remove_file(&p);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_hour_is_well_formed() {
        let s = utc_hour();
        assert_eq!(s.len(), 13, "YYYY-MM-DDTHH = 13 chars, got {s:?}");
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[10..11], "T");
        // The year is sane (this decade or later), proving the civil-date math ran.
        let year: i64 = s[0..4].parse().unwrap();
        assert!(year >= 2025, "year {year} from {s:?}");
    }

    #[test]
    fn json_string_escapes_and_wraps() {
        assert_eq!(json_string("ab"), "\"ab\"");
        assert_eq!(json_string("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(json_string("a\nb"), "\"a\\nb\"");
    }

    #[test]
    fn queued_report_never_contains_the_password() {
        let rest = report_rest("user", "hi \"there\"", &[("state".into(), "Disconnected".into())]);
        assert!(!rest.contains("password"));
        // It must splice into a valid JSON object with the live login.
        let body = format!("{{\"username\":\"u\",\"password\":\"p\",{rest}}}");
        assert!(body.starts_with('{') && body.ends_with('}'));
        assert!(body.contains("\"message\":\"hi \\\"there\\\"\""));
    }

    #[test]
    fn outbox_saves_caps_and_lists_oldest_first() {
        let dir = std::env::temp_dir().join(format!("dn-outbox-test-{}", nonce()));
        for i in 0..(OUTBOX_MAX + 5) {
            outbox_save_in(&dir, &format!("\"kind\":\"t{i}\""));
        }
        assert_eq!(outbox_list_in(&dir).len(), OUTBOX_MAX, "capped");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn env_override_disables() {
        // The env override wins regardless of the runtime flag.
        std::env::set_var("DREAMNAIL_NO_REPORTS", "1");
        assert!(!enabled());
        std::env::remove_var("DREAMNAIL_NO_REPORTS");
    }
}
