# Dreamnail patch to tproxy-config 7.0.7

Used via `[patch.crates-io]` in the workspace `Cargo.toml` (pulled in by
tun2proxy's route setup in the stealth/TUN helper).

**Patch:** `run_command` in `src/lib.rs` sets `CREATE_NO_WINDOW` on Windows.

**Why:** on Windows the helper (`dreamnail-tunhelper`) is built with
`windows_subsystem = "windows"`, i.e. it has no console. tproxy-config sets up
and tears down routes by running `route` (~8x), `netsh` and `powershell`; a
console program started from a console-less parent gets a NEW console window, so
every stealth connect/disconnect flashed several terminal windows. The flag runs
them invisibly; output is still captured (`.output()` pipes stdio).

To upgrade: copy the new crate from the cargo registry, re-apply the hunk above.

**Patch 2 (6.5.3):** `_tproxy_remove` in `src/macos.rs` restores the default
route (unscoped + scoped) FIRST and makes every later cleanup step (bypass host
route deletes, resolv.conf restore, DNS cache flush) best-effort. Upstream
deleted the bypass routes first with `?`, so one failed delete (route already
flushed by a Wi-Fi roam / DHCP renew / sleep) returned early and left the Mac
with no default route after stealth was switched off — "VPN off, no internet".
Setup also: a failed tun-default add puts the original default back instead of returning with none.
