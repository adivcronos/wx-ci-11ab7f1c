//! macOS network self-heal after stealth (TUN) mode is switched off.
//!
//! Field bug (6.5.2, 2026-11-22): on Macs, switching the VPN off could leave the
//! machine with no internet. Three separate ways it broke:
//!
//! 1. **No default route.** tun2proxy's route setup swaps the Mac's default
//!    route for one through the utun device. Its restore deleted temporary host
//!    routes first and bailed out on the first failure, so the original default
//!    route was never put back. Once the utun disappeared there was no route out
//!    at all. (Also patched in `vendor/tproxy-config`.)
//! 2. **Stale hidden DNS.** tun2proxy overwrites the *live* DNS record that
//!    DHCP publishes (`State:/Network/Service/<id>/DNS`) with the tunnel resolver
//!    10.0.0.1. `networksetup` can't see or fix that record, so "Empty" left the
//!    Mac asking a resolver that no longer exists.
//! 3. **DHCP DNS pinned as manual.** The restore wrote the network's DHCP DNS
//!    back as a *manual* setting, so the next Wi-Fi network got the old router's
//!    DNS and nothing resolved.
//!
//! [`heal`] runs as root (from the helper) after every unwind, and also from the
//! `--heal-network` mode the GUI can trigger passwordlessly when it finds the
//! network broken after a crash. Each step is best-effort and verified.
//!
//! The text parsers are platform-neutral so they're unit-tested on Linux.

/// The tunnel's virtual resolver / gateway (tun2proxy default).
pub const TUN_DNS: &str = "10.0.0.1";
/// tun2proxy's default address on the utun device.
pub const TUN_IP: &str = "10.0.0.33";

/// Parse `key : value` lines from `scutil` `show <key>` output (top level only).
pub fn scutil_dict(s: &str) -> Vec<(String, String)> {
    s.lines()
        .filter_map(|l| {
            let (k, v) = l.trim().split_once(" : ")?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

/// The value for `key` in `scutil` `show` output.
pub fn scutil_get(s: &str, key: &str) -> Option<String> {
    scutil_dict(s)
        .into_iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
}

/// IP addresses listed inside an `<array>` in `scutil` `show` output (e.g. the
/// `ServerAddresses` of a DNS record). Picks the `N : <ip>` lines.
pub fn scutil_ips(s: &str) -> Vec<String> {
    s.lines()
        .filter_map(|l| {
            let (k, v) = l.trim().split_once(" : ")?;
            if !k.trim().chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            let v = v.trim();
            v.parse::<std::net::IpAddr>().ok().map(|_| v.to_string())
        })
        .collect()
}

/// Keys from `scutil` `list <pattern>` output (`subKey [0] = State:/...`).
pub fn scutil_keys(s: &str) -> Vec<String> {
    s.lines()
        .filter_map(|l| l.split_once(" = ").map(|(_, k)| k.trim().to_string()))
        .filter(|k| !k.is_empty())
        .collect()
}

/// DNS servers from `ipconfig getpacket <if>`:
/// `domain_name_server (ip_mult): {192.168.1.1, 8.8.8.8}`.
pub fn dhcp_dns(packet: &str) -> Vec<String> {
    for l in packet.lines() {
        let t = l.trim();
        if !t.starts_with("domain_name_server") {
            continue;
        }
        let Some((_, rest)) = t.split_once(':') else { continue };
        return rest
            .trim()
            .trim_start_matches('{')
            .trim_end_matches('}')
            .split(',')
            .map(str::trim)
            .filter(|v| v.parse::<std::net::IpAddr>().is_ok())
            .map(str::to_string)
            .collect();
    }
    Vec::new()
}

/// Servers from `networksetup -getdnsservers <svc>` ("There aren't any…" = none).
pub fn parse_getdnsservers(s: &str) -> Vec<String> {
    s.lines()
        .map(str::trim)
        .filter(|v| v.parse::<std::net::IpAddr>().is_ok())
        .map(str::to_string)
        .collect()
}

/// `(interface, gateway)` from `route -n get default`.
pub fn parse_route_get(s: &str) -> (Option<String>, Option<String>) {
    let mut iface = None;
    let mut gw = None;
    for l in s.lines() {
        if let Some((k, v)) = l.trim().split_once(':') {
            match k.trim() {
                "interface" => iface = Some(v.trim().to_string()),
                "gateway" => gw = Some(v.trim().to_string()),
                _ => {}
            }
        }
    }
    (iface, gw)
}

/// Each active service's manual DNS (the user's own setting), captured BEFORE
/// stealth starts so the exact original can be put back afterwards.
pub type DnsSnapshot = Vec<(String, Vec<String>)>;

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    fn out(cmd: &str, args: &[&str]) -> Option<String> {
        let o = Command::new(cmd).args(args).stderr(Stdio::null()).output().ok()?;
        if !o.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&o.stdout).into_owned())
    }

    fn quiet(cmd: &str, args: &[&str]) -> bool {
        Command::new(cmd)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Feed a script to `scutil` on stdin and return its stdout.
    fn scutil(script: &str) -> String {
        let Ok(mut c) = Command::new("scutil")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        else {
            return String::new();
        };
        if let Some(mut si) = c.stdin.take() {
            let _ = si.write_all(script.as_bytes());
        } // stdin dropped → scutil sees EOF and exits
        c.wait_with_output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default()
    }

    fn services() -> Vec<String> {
        out("networksetup", &["-listallnetworkservices"])
            .unwrap_or_default()
            .lines()
            .skip(1)
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('*'))
            .map(str::to_string)
            .collect()
    }

    fn manual_dns(svc: &str) -> Vec<String> {
        parse_getdnsservers(&out("networksetup", &["-getdnsservers", svc]).unwrap_or_default())
    }

    pub fn snapshot_dns() -> DnsSnapshot {
        services().into_iter().map(|s| { let d = manual_dns(&s); (s, d) }).collect()
    }

    fn set_dns(svc: &str, servers: &[String]) {
        let mut args = vec!["-setdnsservers", svc];
        if servers.is_empty() {
            args.push("Empty");
        } else {
            args.extend(servers.iter().map(String::as_str));
        }
        quiet("networksetup", &args);
    }

    /// Is the default route missing, or pointing at a dead / our own utun?
    fn default_route_broken() -> bool {
        let Some(o) = out("route", &["-n", "get", "default"]) else {
            return true; // "not in table" → no default route at all
        };
        let (iface, _) = parse_route_get(&o);
        let Some(iface) = iface else { return true };
        if !iface.starts_with("utun") {
            return false;
        }
        // A utun can legitimately own the default (another VPN, a Tailscale exit
        // node). Only treat it as ours/stale if it's gone or carries our address.
        match out("ifconfig", &[&iface]) {
            None => true,
            Some(cfg) => cfg.contains(&format!("inet {TUN_IP} ")),
        }
    }

    fn primary() -> (Option<String>, Option<String>) {
        let g = scutil("show State:/Network/Global/IPv4\n");
        (scutil_get(&g, "PrimaryInterface"), scutil_get(&g, "Router"))
    }

    fn heal_route() {
        if !default_route_broken() {
            return;
        }
        let (iface, mut router) = primary();
        if router.is_none() {
            if let Some(i) = &iface {
                router = out("ipconfig", &["getoption", i, "router"]).map(|s| s.trim().to_string());
            }
        }
        let Some(router) = router.filter(|r| r.parse::<std::net::IpAddr>().is_ok()) else {
            log::warn!("macnet: default route missing and no router known");
            return;
        };
        quiet("route", &["-n", "delete", "default"]);
        let ok = quiet("route", &["-n", "add", "default", &router]);
        if let Some(i) = &iface {
            quiet("route", &["-n", "add", "default", &router, "-ifscope", i]);
        }
        log::info!("macnet: restored default route via {router} (ok={ok})");
    }

    /// Repair live (DHCP-published) DNS records still pointing at the tunnel.
    fn heal_state_dns() {
        let keys = scutil_keys(&scutil("list State:/Network/Service/[^/]+/DNS\n"));
        for key in keys {
            let rec = scutil(&format!("show {key}\n"));
            if !scutil_ips(&rec).iter().any(|ip| ip == TUN_DNS) {
                continue;
            }
            let svc_key = key.trim_end_matches("/DNS");
            let ipv4 = scutil(&format!("show {svc_key}/IPv4\n"));
            let real = scutil_get(&ipv4, "InterfaceName")
                .and_then(|i| out("ipconfig", &["getpacket", &i]))
                .map(|p| dhcp_dns(&p))
                .unwrap_or_default();
            if real.is_empty() {
                // No DHCP resolver to go back to: drop the stale record; the
                // verification step below pins a public one if nothing's left.
                scutil(&format!("remove {key}\n"));
                log::info!("macnet: removed stale tunnel DNS record {key}");
            } else {
                scutil(&format!(
                    "get {key}\nd.add ServerAddresses * {}\nset {key}\n",
                    real.join(" ")
                ));
                log::info!("macnet: restored DHCP DNS {} on {key}", real.join(","));
            }
        }
    }

    fn has_real_resolver() -> bool {
        out("scutil", &["--dns"])
            .map(|o| crate::diag::parse_scutil_dns(&o).into_iter().any(|s| s != TUN_DNS))
            .unwrap_or(false)
    }

    fn flush() {
        quiet("dscacheutil", &["-flushcache"]);
        quiet("killall", &["-HUP", "mDNSResponder"]);
    }

    /// Does the network look broken in the ways a dead stealth session leaves it?
    /// Cheap and unprivileged — safe for the GUI to poll.
    pub fn looks_broken() -> bool {
        if default_route_broken() {
            return true;
        }
        let dns = out("scutil", &["--dns"])
            .map(|o| crate::diag::parse_scutil_dns(&o))
            .unwrap_or_default();
        dns.iter().any(|s| s == TUN_DNS)
    }

    /// Full repair. Needs root. `snapshot` = the user's manual DNS from before
    /// the session (None = unknown: only clear manual entries that are the tunnel
    /// resolver, leave the user's own settings alone).
    pub fn heal(snapshot: Option<&DnsSnapshot>) {
        heal_route();

        // Manual (Setup) DNS: put back exactly what the user had; never leave the
        // tunnel resolver or tun2proxy's "DHCP DNS pinned as manual" in place.
        let mut emptied: Vec<String> = Vec::new();
        match snapshot {
            Some(snap) => {
                for (svc, orig) in snap {
                    let keep: Vec<String> =
                        orig.iter().filter(|s| *s != TUN_DNS).cloned().collect();
                    if manual_dns(svc) != keep {
                        set_dns(svc, &keep);
                    }
                    if keep.is_empty() {
                        emptied.push(svc.clone());
                    }
                }
            }
            None => {
                for svc in services() {
                    let cur = manual_dns(&svc);
                    if cur.iter().any(|s| s == TUN_DNS) {
                        set_dns(&svc, &[]);
                        emptied.push(svc);
                    } else if cur.is_empty() {
                        emptied.push(svc);
                    }
                }
            }
        }

        heal_state_dns();
        flush();

        // Verify: there must be a real resolver now. If not (Wi-Fi hands out no
        // DNS — the 6.5.1 field case), pin a public one on the services that have
        // no manual DNS rather than leaving the Mac dark.
        std::thread::sleep(Duration::from_millis(600));
        if !has_real_resolver() {
            let one = ["1.1.1.1".to_string(), "1.0.0.1".to_string()];
            for svc in &emptied {
                set_dns(svc, &one);
            }
            flush();
            log::info!("macnet: no resolver after reset — pinned 1.1.1.1/1.0.0.1");
        }
        log::info!("macnet: network heal done");
    }
}

#[cfg(target_os = "macos")]
pub use imp::{heal, looks_broken, snapshot_dns};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_global_ipv4() {
        let s = "<dictionary> {\n  PrimaryInterface : en0\n  PrimaryService : 8A3C-11\n  Router : 192.168.1.1\n}\n";
        assert_eq!(scutil_get(s, "Router").as_deref(), Some("192.168.1.1"));
        assert_eq!(scutil_get(s, "PrimaryInterface").as_deref(), Some("en0"));
    }

    #[test]
    fn parses_dns_record_ips() {
        let s = "<dictionary> {\n  ServerAddresses : <array> {\n    0 : 10.0.0.1\n    1 : 1.1.1.1\n  }\n  SearchDomains : <array> {\n    0 : lan\n  }\n}\n";
        assert_eq!(scutil_ips(s), vec!["10.0.0.1", "1.1.1.1"]);
    }

    #[test]
    fn parses_key_list() {
        let s = "  subKey [0] = State:/Network/Service/AAA/DNS\n  subKey [1] = State:/Network/Service/BBB/DNS\n";
        assert_eq!(scutil_keys(s), vec!["State:/Network/Service/AAA/DNS", "State:/Network/Service/BBB/DNS"]);
    }

    #[test]
    fn parses_dhcp_packet_dns() {
        let p = "op = BOOTREPLY\nrouter (ip_mult): {192.168.1.1}\ndomain_name_server (ip_mult): {192.168.1.1, 8.8.8.8}\n";
        assert_eq!(dhcp_dns(p), vec!["192.168.1.1", "8.8.8.8"]);
        assert!(dhcp_dns("op = BOOTREPLY\n").is_empty());
    }

    #[test]
    fn parses_networksetup_dns() {
        assert!(parse_getdnsservers("There aren't any DNS Servers set on Wi-Fi.\n").is_empty());
        assert_eq!(parse_getdnsservers("1.1.1.1\n1.0.0.1\n"), vec!["1.1.1.1", "1.0.0.1"]);
    }

    #[test]
    fn parses_route_get() {
        let s = "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>\n";
        let (i, g) = parse_route_get(s);
        assert_eq!(i.as_deref(), Some("en0"));
        assert_eq!(g.as_deref(), Some("192.168.1.1"));
    }
}
