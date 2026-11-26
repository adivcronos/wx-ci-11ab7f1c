//! `RusshTunnel` — the real SSH local-forward adapter for the core `Tunnel` port.
//!
//! Reproduces the Python backend's tunnel: an SSH connection to the server with
//! a LOCAL forward `127.0.0.1:10809` → (over SSH) → server `127.0.0.1:10808`
//! (the loopback-only VLESS inbound). The local Xray then dials 10809.
//!
//! russh is async (tokio); the core `Tunnel` trait is sync, so this adapter owns
//! a small tokio runtime and `block_on`s the connect/auth/bind, then leaves an
//! accept loop running on that runtime forwarding each local connection over its
//! own `direct-tcpip` channel. `alive()` reports the live SSH session state
//! (`Handle::is_closed`), which — with keepalives — is what the engine's watchdog
//! uses to notice a dropped link and reconnect.
//!
//! The server's host key is PINNED (see `ClientHandler::check_server_key`), and
//! the whole path is verified live against the real server.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dreamnail_core::ports::{Credentials, EngineError, Result, Tunnel};
use russh::client::{self, Config, Handle};
use russh::keys::{HashAlg, PublicKey, PublicKeyOrCertificate};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;

/// The server's SSH host key (ed25519), pinned so a MITM on port 22 can't
/// impersonate it. Same value the CI deploy step pins in build-v2.yml.
const SERVER_HOST_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG0qf9UMzuFxoPZnUaQDUs4Cshccs8dqsqNrjmP1SHf7";

/// The pinned server SSH host key, for other modules that open their own SSH
/// session to the same server (e.g. the remote-access reverse link).
pub(crate) fn server_host_key() -> &'static str {
    SERVER_HOST_KEY
}

/// Where the tunnel connects and what it forwards. Defaults match the Python
/// backend's config.py (SSH_HOST/PORT, TUNNEL_LOCAL_*, TUNNEL_REMOTE_*).
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub host: String,
    pub port: u16,
    pub local_host: String,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    pub connect_timeout: Duration,
    pub keepalive: Duration,
    /// Pinned server host key in OpenSSH format. `None` disables pinning (accepts
    /// any key — for tests/dev only). Defaults to the real server's key.
    pub host_key: Option<String>,
    /// Optional SECOND local forward for the UDP gateway (udpgw): local
    /// `udpgw_local_port` → server `udpgw_remote_host:udpgw_remote_port`. This is
    /// how the TUN helper reaches the server-side `udpgw-server` to carry UDP over
    /// TCP. `None` disables it (UDP then falls back to SOCKS UDP-associate, which
    /// is broken on macOS — so the client sets this by default).
    pub udpgw_local_port: Option<u16>,
    pub udpgw_remote_host: String,
    pub udpgw_remote_port: u16,
    /// The port-443 "backup door": the same SSH, wrapped in TLS (ALPN `dn1`),
    /// for networks that block port 22 (schools, workplaces, hotels). The
    /// server's nginx passes it to sshd; to anyone else 443 is the website.
    /// `None` = never use it.
    pub tls_port: Option<u16>,
    /// The "looks like a website" backup door: SSH inside a WebSocket inside TLS
    /// on `tls_port`. For networks that pass only ordinary-looking web traffic.
    /// `None` = never use it. Holds the request path (`WS_PATH`).
    pub ws_path: Option<String>,
    /// Which door the sessions use. `open()` picks it (last one that worked
    /// first, then the others) — callers leave the default.
    pub via: Via,
}

/// How the SSH connection reaches the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// Plain SSH on `port` (22).
    Direct,
    /// SSH inside TLS on `tls_port` (443), selected by ALPN `dn1`.
    Tls,
    /// SSH inside a WebSocket inside TLS on `tls_port` — reads as a normal
    /// long-lived HTTPS web request, so it survives networks that inspect 443.
    Ws,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            host: "66.226.144.136".into(),
            port: 22,
            local_host: "127.0.0.1".into(),
            local_port: 10809,
            remote_host: "127.0.0.1".into(),
            remote_port: 10808,
            connect_timeout: Duration::from_secs(10),
            keepalive: Duration::from_secs(10),
            host_key: Some(SERVER_HOST_KEY.into()),
            udpgw_local_port: Some(crate::netcfg::UDPGW_LOCAL_PORT),
            udpgw_remote_host: crate::netcfg::UDPGW_REMOTE_HOST.into(),
            udpgw_remote_port: crate::netcfg::UDPGW_REMOTE_PORT,
            tls_port: Some(443),
            ws_path: Some(crate::netcfg::WS_PATH.into()),
            via: Via::Direct,
        }
    }
}

/// SSH client callbacks. `expected` holds the pinned host key (if any); the
/// server's key must match it by SHA-256 fingerprint or the connection is
/// refused — defeating a MITM on port 22.
struct ClientHandler {
    expected: Option<PublicKey>,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        let Some(expected) = &self.expected else {
            return Ok(true); // pinning disabled
        };
        match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => {
                Ok(key.fingerprint(HashAlg::Sha256) == expected.fingerprint(HashAlg::Sha256))
            }
            // We only use plain host keys, never certificates.
            PublicKeyOrCertificate::Certificate(_) => Ok(false),
        }
    }
}

/// SSH cipher preference. `DREAMNAIL_SSH_CIPHER=chacha|aes` overrides (bench
/// hook); default is set below from measurements.
fn ssh_preferred() -> russh::Preferred {
    use russh::cipher;
    let mut p = russh::Preferred::default();
    let aes_first: &'static [cipher::Name] =
        &[cipher::AES_256_GCM, cipher::AES_128_GCM, cipher::CHACHA20_POLY1305];
    let chacha_first: &'static [cipher::Name] =
        &[cipher::CHACHA20_POLY1305, cipher::AES_256_GCM, cipher::AES_128_GCM];
    p.cipher = std::borrow::Cow::Borrowed(match std::env::var("DREAMNAIL_SSH_CIPHER").as_deref() {
        Ok("chacha") => chacha_first,
        Ok("aes") => aes_first,
        _ => chacha_first,
    });
    p
}

/// SSH channel receive window. `DREAMNAIL_SSH_WINDOW` (bytes) overrides.
fn ssh_window() -> u32 {
    std::env::var("DREAMNAIL_SSH_WINDOW")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2 * 1024 * 1024)
}

/// How many SSH sessions carry web traffic ("stripes"). Every local connection
/// rides whichever live session has the fewest open channels, so one lost
/// packet on a patchy link only stalls the connections on ONE session instead
/// of every tab at once (everything sharing a single TCP socket is what makes
/// a lossy Wi-Fi feel frozen). Extra sessions are opened in the background
/// AFTER the main one is up and are pure bonus: if they fail, the tunnel works
/// exactly as a single session. `DREAMNAIL_STRIPES` overrides (1 = old behaviour).
/// How mux interacts with striping (see `browsing_mux` + the `vless-bulk`
/// outbound in xray.rs): bulk transfers use a NON-muxed outbound, so each of
/// their connections lands on its own (least-busy) stripe for full throughput;
/// ordinary browsing uses the muxed outbound, which packs its many small
/// requests onto one stripe — fine, since browsing is latency-bound, not
/// throughput-bound.
const DEFAULT_STRIPES: usize = 3;

/// How many web stripes weak-network mode opens — the clamp ceiling, so a lossy
/// link spreads connections as widely as possible.
const WEAKNET_STRIPES: usize = 6;

pub(crate) fn stripes() -> usize {
    std::env::var("DREAMNAIL_STRIPES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            if weaknet_mode() {
                WEAKNET_STRIPES
            } else {
                DEFAULT_STRIPES
            }
        })
        .clamp(1, 6)
}

type Session = Arc<Handle<ClientHandler>>;

struct Member {
    h: Session,
    active: Arc<AtomicUsize>, // channels currently open on this session
    health: Arc<Health>,
}

/// Live health of one SSH session, learned from how long opening a channel on
/// it takes. A channel open is a full round-trip *through that session's TCP
/// stream*, so when a lost packet on jumpy Wi-Fi stalls the stream (everything
/// queued behind the retransmit), opens on it slow down first — the earliest,
/// cheapest signal that the session is stuck.
struct Health {
    /// Smoothed channel-open time, ms (EWMA, 1/4 weight per sample).
    open_ms: AtomicU32,
    /// Opens in flight on this session that haven't answered yet. A session
    /// with an overdue open is treated as stalled until it answers.
    pending: AtomicUsize,
}

impl Health {
    fn new() -> Arc<Self> {
        Arc::new(Self { open_ms: AtomicU32::new(0), pending: AtomicUsize::new(0) })
    }
    fn record(&self, ms: u32) {
        let old = self.open_ms.load(Ordering::Relaxed);
        let new = if old == 0 { ms } else { (old * 3 + ms) / 4 };
        self.open_ms.store(new, Ordering::Relaxed);
    }
    /// Lower = better. Each open channel costs a little (spread load); a slow
    /// or currently-stuck session costs a lot (steer new work away from it).
    fn score(&self, active: usize) -> u64 {
        let stuck = self.pending.load(Ordering::Relaxed) as u64 * 1000;
        u64::from(self.open_ms.load(Ordering::Relaxed)) + active as u64 * 25 + stuck
    }
}

/// How long a new connection waits on its first-choice session before ALSO
/// trying the next-best one ("racing" the open; first to answer wins). Normal:
/// 300 ms — long enough that a healthy open (one RTT, ~10-60 ms) never races;
/// bad-Wi-Fi mode races sooner. `DREAMNAIL_HEDGE_MS` overrides (0 = never race).
fn hedge_after() -> Option<Duration> {
    let ms = std::env::var("DREAMNAIL_HEDGE_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(if weaknet_mode() { 150 } else { 300 });
    (ms > 0).then(|| Duration::from_millis(ms))
}

/// The SSH sessions a forward may use. `balanced` = pick the least-busy live
/// session (web stripes); otherwise members are tried in order (the udpgw
/// forward: game lane first, main session as fallback).
struct Pool {
    members: Mutex<Vec<Member>>,
    balanced: bool,
}

impl Pool {
    fn new(sessions: Vec<Session>, balanced: bool) -> Arc<Self> {
        let members = sessions
            .into_iter()
            .map(|h| Member { h, active: Arc::new(AtomicUsize::new(0)), health: Health::new() })
            .collect();
        Arc::new(Self { members: Mutex::new(members), balanced })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Member>> {
        self.members.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn add(&self, h: Session) {
        let mut m = self.lock();
        m.retain(|x| !x.h.is_closed()); // forget sessions that have died
        m.push(Member { h, active: Arc::new(AtomicUsize::new(0)), health: Health::new() });
    }

    fn live(&self) -> usize {
        self.lock().iter().filter(|x| !x.h.is_closed()).count()
    }

    /// Live sessions, best first. The sort is stable, so ties keep the main
    /// session (index 0) in front.
    fn candidates(&self) -> Vec<Cand> {
        let mut v: Vec<_> = self
            .lock()
            .iter()
            .filter(|x| !x.h.is_closed())
            .map(|x| Cand { h: x.h.clone(), active: x.active.clone(), health: x.health.clone() })
            .collect();
        if self.balanced {
            v.sort_by_key(|c| c.health.score(c.active.load(Ordering::Relaxed)));
        }
        v
    }

    fn drain(&self) -> Vec<Session> {
        std::mem::take(&mut *self.lock()).into_iter().map(|m| m.h).collect()
    }
}

#[derive(Clone)]
struct Cand {
    h: Session,
    active: Arc<AtomicUsize>,
    health: Arc<Health>,
}

type Chan = russh::Channel<russh::client::Msg>;

/// Open a direct-tcpip channel on one session, feeding the result into its
/// health score. `pending` stays raised for as long as the open is outstanding,
/// so a session whose opens hang is steered around by every OTHER new
/// connection immediately — not only after the timeout.
async fn timed_open(c: Cand, rhost: String, rport: u32, lport: u32) -> Option<(Chan, Cand)> {
    struct Pending(Arc<Health>);
    impl Drop for Pending {
        fn drop(&mut self) {
            self.0.pending.fetch_sub(1, Ordering::Relaxed);
        }
    }
    c.health.pending.fetch_add(1, Ordering::Relaxed);
    let _p = Pending(c.health.clone());
    let t0 = std::time::Instant::now();
    let r = c.h.channel_open_direct_tcpip(rhost, rport, "127.0.0.1", lport).await;
    let ms = t0.elapsed().as_millis().min(u128::from(u32::MAX)) as u32;
    match r {
        Ok(ch) => {
            c.health.record(ms);
            Some((ch, c))
        }
        Err(_) => {
            c.health.record(ms.max(2000)); // a failed open is as bad as a very slow one
            None
        }
    }
}

/// Open a channel for a new connection, racing a second session if the first
/// choice hasn't answered within [`hedge_after`]. Falls through the rest of the
/// candidates in order if both fail.
///
/// Each open runs as its own task and is NEVER abandoned mid-flight: the losing
/// open is handed to [`reap`], which waits for it and closes the channel if it
/// opened after all. (Dropping a pending open would leave a stray channel open
/// on the server — the same class of leak 5.6.0 fixed for sessions.)
async fn open_best(cands: Vec<Cand>, rhost: &str, rport: u32, lport: u32) -> Option<(Chan, Cand)> {
    let mut it = cands.into_iter();
    let first = it.next()?;
    let mut a = tokio::spawn(timed_open(first, rhost.to_string(), rport, lport));
    let delay = hedge_after();
    let second = if delay.is_some() { it.next() } else { None };
    if let (Some(d), Some(sec)) = (delay, second) {
        tokio::select! {
            r = &mut a => {
                if let Ok(Some(ok)) = r { return Some(ok); }
                // First choice failed fast: the second becomes the primary.
                if let Some(ok) = timed_open(sec, rhost.to_string(), rport, lport).await {
                    return Some(ok);
                }
            }
            _ = tokio::time::sleep(d) => {
                let mut b = tokio::spawn(timed_open(sec, rhost.to_string(), rport, lport));
                let (mut a_done, mut b_done) = (false, false);
                while !(a_done && b_done) {
                    tokio::select! {
                        r = &mut a, if !a_done => {
                            a_done = true;
                            if let Ok(Some(ok)) = r {
                                if !b_done { reap(b); }
                                return Some(ok);
                            }
                        }
                        r = &mut b, if !b_done => {
                            b_done = true;
                            if let Ok(Some(ok)) = r {
                                if !a_done { reap(a); }
                                return Some(ok);
                            }
                        }
                    }
                }
            }
        }
    } else if let Ok(Some(ok)) = a.await {
        return Some(ok);
    }
    for c in it {
        if let Some(ok) = timed_open(c, rhost.to_string(), rport, lport).await {
            return Some(ok);
        }
    }
    None
}

/// Let a losing open finish in the background and close its channel if it
/// opened, so the race never leaves anything dangling on the server.
fn reap(h: JoinHandle<Option<(Chan, Cand)>>) {
    tokio::spawn(async move {
        if let Ok(Some((ch, _))) = h.await {
            let _ = ch.close().await;
        }
    });
}

/// How long a pre-opened spare channel may wait for a connection. Each spare
/// is a live TCP connection from the server's sshd to Xray, and Xray drops a
/// connection that hasn't spoken for 60 s, so spares are retired well before.
const SPARE_TTL: Duration = Duration::from_secs(40);

/// How many channels to keep opened-and-waiting on the web forward.
/// Bad-Wi-Fi mode turns Xray's mux off (one lost packet on a shared stream
/// would freeze every request on it), so every new browser connection needs
/// its own channel — a round trip to the server before the first byte, which
/// is what made pages "slow at first, then zoom". With spares ready, a new
/// connection takes one instantly. Normal mode has mux, so none are kept.
/// `DREAMNAIL_SPARES` overrides (0 = off).
fn spare_target() -> usize {
    std::env::var("DREAMNAIL_SPARES")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(if weaknet_mode() { 6 } else { 0 })
        .min(16)
}

struct Spare {
    ch: Chan,
    c: Cand,
    born: std::time::Instant,
    // Counts the spare as load on its session while it waits, so the best-
    // session pick spreads spares (and the connections that take them) across
    // stripes instead of piling every one onto the same session.
    _load: ActiveGuard,
}

impl Spare {
    fn fresh(&self) -> bool {
        self.born.elapsed() < SPARE_TTL && !self.c.h.is_closed()
    }
    /// Usable right now: fresh, and its session isn't sitting on an overdue
    /// open (a stalled stream). A spare on a stuck session would hand the
    /// connection straight into the stall, skipping the race that avoids it.
    fn ready(&self) -> bool {
        self.fresh() && self.c.health.pending.load(Ordering::Relaxed) == 0
    }
}

/// Channels opened ahead of time, waiting for the next local connection.
#[derive(Default)]
struct Spares {
    q: Mutex<std::collections::VecDeque<Spare>>,
    taken: tokio::sync::Notify,
}

impl Spares {
    fn lock(&self) -> std::sync::MutexGuard<'_, std::collections::VecDeque<Spare>> {
        self.q.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A ready spare on the least-loaded healthy session, if any. Stale ones
    /// are closed in the background; ones on a momentarily stuck session stay
    /// queued (they're fine once it recovers) and the caller races instead.
    fn take(&self) -> Option<(Chan, Cand)> {
        let mut got = None;
        let stale = self.expire();
        {
            let mut q = self.lock();
            let best = q
                .iter()
                .enumerate()
                .filter(|(_, s)| s.ready())
                .min_by_key(|(_, s)| s.c.health.score(s.c.active.load(Ordering::Relaxed)))
                .map(|(i, _)| i);
            if let Some(s) = best.and_then(|i| q.remove(i)) {
                got = Some((s.ch, s.c));
            }
        }
        close_all(stale);
        if got.is_some() {
            self.taken.notify_one(); // ask the keeper to top back up
        }
        got
    }

    /// Remove (and return) spares that are too old to trust.
    fn expire(&self) -> Vec<Chan> {
        let mut q = self.lock();
        let (keep, old): (Vec<_>, Vec<_>) = q.drain(..).partition(Spare::fresh);
        q.extend(keep);
        old.into_iter().map(|s| s.ch).collect()
    }
}

fn close_all(chans: Vec<Chan>) {
    if chans.is_empty() {
        return;
    }
    tokio::spawn(async move {
        for ch in chans {
            let _ = ch.close().await;
        }
    });
}

/// Keeps `spare_target()` channels opened and waiting on the best session,
/// replacing each one as it is used or ages out. Runs as a child of the forward,
/// so close() aborts it with the relays (its channels die with the sessions).
async fn keep_spares(pool: Arc<Pool>, spares: Arc<Spares>, rhost: String, rport: u32, lport: u32) {
    loop {
        close_all(spares.expire());
        let want = spare_target();
        let have = spares.lock().len();
        if have < want {
            let best = pool.candidates().into_iter().next();
            match best {
                Some(c) => match timed_open(c, rhost.clone(), rport, lport).await {
                    Some((ch, c)) => {
                        let load = ActiveGuard::new(c.active.clone());
                        spares.lock().push_back(Spare { ch, c, born: std::time::Instant::now(), _load: load });
                        continue;
                    }
                    None => tokio::time::sleep(Duration::from_secs(1)).await,
                },
                None => tokio::time::sleep(Duration::from_secs(1)).await,
            }
            continue;
        }
        // Full (or disabled): sleep until one is taken or the oldest needs replacing.
        let wait = spares
            .lock()
            .front()
            .map(|s| SPARE_TTL.saturating_sub(s.born.elapsed()))
            .unwrap_or(Duration::from_secs(5))
            .clamp(Duration::from_millis(200), Duration::from_secs(5));
        tokio::select! {
            _ = spares.taken.notified() => {}
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

/// Counts a channel as open on its session for as long as it lives.
struct ActiveGuard(Arc<AtomicUsize>);

impl ActiveGuard {
    fn new(a: Arc<AtomicUsize>) -> Self {
        a.fetch_add(1, Ordering::Relaxed);
        Self(a)
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct RusshTunnel {
    cfg: TunnelConfig,
    rt: Runtime,
    handle: Option<Session>,
    // Dedicated "game lane" SSH session carrying ONLY the udpgw forward, so game
    // UDP never queues behind bulk traffic in the main session's TCP socket.
    lane: Option<Session>,
    // Sessions striping the web forward (main + background extras).
    web: Option<Arc<Pool>>,
    accept_task: Option<JoinHandle<()>>,
    // Second accept loop for the udpgw forward (None if udpgw is disabled).
    udpgw_task: Option<JoinHandle<()>>,
    // Background task that opens (and re-opens) the extra web stripes.
    stripe_task: Option<JoinHandle<()>>,
    // Per-connection relay tasks (one per forwarded local connection). Each holds
    // a clone of the SSH session it rides, so if it outlives teardown the session
    // never drops — the server keeps the sshd-session alive (answering keepalives)
    // and stale tunnels pile up. close() aborts these so their session clones are
    // released and the server reaps the sessions.
    children: Arc<Mutex<Vec<JoinHandle<()>>>>,
    // True when this bring-up is the Reality door (no SSH; Xray does VLESS+
    // Reality straight to :443). alive() then rests on Xray, not an SSH session.
    reality: bool,
    // Flipped false once close() runs; alive() also consults the live session.
    opened: Arc<AtomicBool>,
}

impl RusshTunnel {
    pub fn new(cfg: TunnelConfig) -> Result<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| EngineError::Tunnel(format!("runtime init: {e}")))?;
        Ok(Self {
            cfg,
            rt,
            handle: None,
            lane: None,
            web: None,
            accept_task: None,
            udpgw_task: None,
            stripe_task: None,
            children: Arc::new(Mutex::new(Vec::new())),
            reality: false,
            opened: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Switch this bring-up to the Reality door: no SSH session, Xray will speak
    /// VLESS+Reality straight to the server. The "tunnel" is just a marker; its
    /// liveness rests on Xray from here (see `alive`).
    fn engage_reality(&mut self, creds: &Credentials) -> Result<()> {
        // The Reality door only lets a customer in with their own SECRET id,
        // which the server hands out via /api/me (password-checked). No id yet
        // (first ever connect, or upgraded from an older build) → ask for it
        // now; if that fails too, stop cleanly instead of bringing stealth up
        // on a door that would turn us away (that was the "no internet" bug).
        if crate::xray::cached_reality_id(&creds.username).is_none() {
            let _ = crate::entitlements::fetch(crate::netcfg::API_HOST, &creds.username, &creds.password);
        }
        if crate::xray::cached_reality_id(&creds.username).is_none() {
            return Err(EngineError::Tunnel(
                "server unreachable on 22 and 443; the backup door needs one normal connection first".into(),
            ));
        }
        set_reality_mode(true);
        self.reality = true;
        self.handle = None;
        self.lane = None;
        self.web = None;
        self.accept_task = None;
        self.udpgw_task = None;
        self.stripe_task = None;
        ACTIVE_PORT.store(self.cfg.tls_port.unwrap_or(crate::netcfg::REALITY_PORT), Ordering::Relaxed);
        self.opened.store(true, Ordering::SeqCst);
        Ok(())
    }
}

/// ALPN token that tells the server's nginx "this is the app, not a browser".
const DOOR_ALPN: &[u8] = b"dn1";

/// The server port the live tunnel uses (22, or 443 via the backup door), so
/// the signal meter can ping the door that's actually open on this network.
static ACTIVE_PORT: AtomicU16 = AtomicU16::new(22);

pub fn active_port() -> u16 {
    ACTIVE_PORT.load(Ordering::Relaxed)
}

/// True while the tunnel is running in Reality mode: no SSH, the local Xray
/// speaks VLESS+Reality straight to the server:443. `build_xray_config` reads
/// this to pick the outbound. Set by `open()` when the SSH doors are all
/// unreachable (or forced via `DREAMNAIL_DOOR=reality`); cleared by `close()`.
static REALITY_MODE: AtomicBool = AtomicBool::new(false);

pub fn reality_mode() -> bool {
    REALITY_MODE.load(Ordering::Relaxed)
}

fn set_reality_mode(on: bool) {
    REALITY_MODE.store(on, Ordering::Relaxed);
}

/// Whether the Reality door may be used at all (shipped keys + not disabled).
fn reality_enabled() -> bool {
    std::env::var("DREAMNAIL_REALITY").as_deref() != Ok("0")
}

/// Accepts any certificate. Safe here because the TLS layer is only a wrapper
/// that gets SSH through a port-22 block: the SSH inside still verifies the
/// PINNED server host key (`ClientHandler::check_server_key`), so a middlebox
/// that intercepts the TLS still can't impersonate the server. Not verifying
/// also means a lapsed web certificate can never take the backup door down.
#[derive(Debug)]
struct AnyCert;

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _server_name: &tokio_rustls::rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> std::result::Result<
        tokio_rustls::rustls::client::danger::ServerCertVerified,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> std::result::Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> std::result::Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        tokio_rustls::rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn door_connector() -> Result<tokio_rustls::TlsConnector> {
    use tokio_rustls::rustls;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| EngineError::Tunnel(format!("tls config: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert))
        .with_no_client_auth();
    tls.alpn_protocols = vec![DOOR_ALPN.to_vec()];
    Ok(tokio_rustls::TlsConnector::from(Arc::new(tls)))
}

/// TLS for the WebSocket door: ALPN `http/1.1` so the handshake reads like a
/// browser opening an ordinary HTTPS connection (the `dn1` ALPN of the plain-TLS
/// door would itself stand out to an inspecting middlebox).
fn ws_tls_connector() -> Result<tokio_rustls::TlsConnector> {
    use tokio_rustls::rustls;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| EngineError::Tunnel(format!("tls config: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsConnector::from(Arc::new(tls)))
}

/// Presents a WebSocket as a plain byte stream so russh can run SSH over it.
/// Outbound bytes become one binary frame per write; inbound binary frames are
/// buffered and handed back as a byte stream. Ping/Pong/Text frames are ignored
/// (tokio-tungstenite answers pings itself), and Close / end-of-stream reads as
/// EOF. All fields are `Unpin`, so the adapter is `Unpin` as russh requires.
struct WsByteStream<S> {
    inner: tokio_tungstenite::WebSocketStream<S>,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl<S> WsByteStream<S> {
    fn new(inner: tokio_tungstenite::WebSocketStream<S>) -> Self {
        Self { inner, read_buf: Vec::new(), read_pos: 0 }
    }
}

impl<S> tokio::io::AsyncRead for WsByteStream<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use futures_util::Stream;
        use std::task::Poll;
        use tokio_tungstenite::tungstenite::Message;
        loop {
            // Drain whatever is already buffered from a previous frame first.
            if self.read_pos < self.read_buf.len() {
                let n = std::cmp::min(buf.remaining(), self.read_buf.len() - self.read_pos);
                let start = self.read_pos;
                buf.put_slice(&self.read_buf[start..start + n]);
                self.read_pos += n;
                return Poll::Ready(Ok(()));
            }
            match std::pin::Pin::new(&mut self.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(Message::Binary(data)))) => {
                    if data.is_empty() {
                        continue; // keep-alive-ish empty frame; wait for real data
                    }
                    self.read_buf = data;
                    self.read_pos = 0;
                }
                Poll::Ready(Some(Ok(Message::Close(_))) | None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Ok(_))) => continue, // ping/pong/text — ignore
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(std::io::Error::other(e)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> tokio::io::AsyncWrite for WsByteStream<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use futures_util::Sink;
        use std::task::Poll;
        use tokio_tungstenite::tungstenite::Message;
        match std::pin::Pin::new(&mut self.inner).poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                match std::pin::Pin::new(&mut self.inner).start_send(Message::Binary(buf.to_vec())) {
                    Ok(()) => Poll::Ready(Ok(buf.len())),
                    Err(e) => Poll::Ready(Err(std::io::Error::other(e))),
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use futures_util::Sink;
        std::pin::Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map_err(std::io::Error::other)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use futures_util::Sink;
        std::pin::Pin::new(&mut self.inner)
            .poll_close(cx)
            .map_err(std::io::Error::other)
    }
}

/// SSH connect + key exchange (no auth yet) through `cfg.via`, bounded by
/// `timeout`.
async fn handshake_via(
    config: Arc<Config>,
    cfg: &TunnelConfig,
    expected: Option<PublicKey>,
    via: Via,
    timeout: Duration,
) -> Result<Handle<ClientHandler>> {
    let nodelay = config.nodelay;
    let go = async move {
        let handler = ClientHandler { expected };
        let port = match via {
            Via::Direct => cfg.port,
            Via::Tls | Via::Ws => {
                cfg.tls_port.ok_or_else(|| EngineError::Tunnel("no backup door".into()))?
            }
        };
        // The WebSocket door rides Cloudflare: it connects to the proxied
        // hostname (WS_HOST, which resolves to Cloudflare's anycast IPs), not the
        // origin. Every other door goes straight to the origin host.
        let conn_host = if matches!(via, Via::Ws) {
            crate::netcfg::WS_HOST
        } else {
            cfg.host.as_str()
        };
        let tcp = TcpStream::connect((conn_host, port))
            .await
            .map_err(|e| EngineError::Tunnel(format!("{e:?}")))?;
        if nodelay {
            let _ = tcp.set_nodelay(true);
        }
        let ssh = match via {
            Via::Direct => client::connect_stream(config, tcp, handler).await,
            Via::Tls => {
                let ip: std::net::IpAddr = cfg
                    .host
                    .parse()
                    .map_err(|e| EngineError::Tunnel(format!("backup door host: {e}")))?;
                let tls = door_connector()?
                    .connect(ip.into(), tcp)
                    .await
                    .map_err(|e| EngineError::Tunnel(format!("backup door tls: {e:?}")))?;
                client::connect_stream(config, tls, handler).await
            }
            Via::Ws => {
                use tokio_rustls::rustls::pki_types::ServerName;
                use tokio_tungstenite::tungstenite::client::IntoClientRequest;
                use tokio_tungstenite::tungstenite::http::HeaderValue;
                let path = cfg
                    .ws_path
                    .clone()
                    .ok_or_else(|| EngineError::Tunnel("no ws door".into()))?;
                // Cloudflare routes by SNI, so present the proxied hostname (a
                // DnsName, not an IP) — that's how the edge knows to forward this
                // WebSocket to our origin.
                let sni = ServerName::try_from(crate::netcfg::WS_HOST)
                    .map_err(|e| EngineError::Tunnel(format!("ws door sni: {e}")))?;
                let tls = ws_tls_connector()?
                    .connect(sni, tcp)
                    .await
                    .map_err(|e| EngineError::Tunnel(format!("ws door tls: {e:?}")))?;
                // A plausible-looking upgrade request. Built from the URL so
                // tungstenite fills in Host and the mandatory Sec-WebSocket-Key /
                // Version / Upgrade / Connection headers; we add an Origin and a
                // browser User-Agent so it reads like normal web traffic. Host is
                // our server's own address (netcfg::WS_HOST).
                let host = crate::netcfg::WS_HOST;
                let mut req = format!("wss://{host}{path}")
                    .into_client_request()
                    .map_err(|e| EngineError::Tunnel(format!("ws request: {e}")))?;
                let h = req.headers_mut();
                if let Ok(v) = HeaderValue::from_str(&format!("https://{host}")) {
                    h.insert("Origin", v);
                }
                h.insert(
                    "User-Agent",
                    HeaderValue::from_static(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                         (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
                    ),
                );
                let (ws, _resp) = tokio_tungstenite::client_async(req, tls)
                    .await
                    .map_err(|e| EngineError::Tunnel(format!("ws door upgrade: {e:?}")))?;
                client::connect_stream(config, WsByteStream::new(ws), handler).await
            }
        };
        ssh.map_err(|e| EngineError::Tunnel(format!("{e:?}")))
    };
    tokio::time::timeout(timeout, go)
        .await
        .map_err(|_| EngineError::Tunnel("connect timed out".into()))?
}

/// SSH connect + key exchange through the door `open()` settled on.
async fn handshake(
    config: Arc<Config>,
    cfg: &TunnelConfig,
    expected: Option<PublicKey>,
) -> Result<Handle<ClientHandler>> {
    handshake_via(config, cfg, expected, cfg.via, cfg.connect_timeout).await
}

/// The doors to try, best first: the last one that worked on this device, then
/// the rest. Default order is cheapest-first — plain SSH (22), then TLS on 443,
/// then WebSocket on 443 (most disguise, most overhead). All-but-last get a
/// short timeout in `open()`, so a blocked port doesn't stall the button.
/// `DREAMNAIL_DOOR=22|443|ws` forces one (tests).
fn door_order(cfg: &TunnelConfig) -> Vec<Via> {
    if cfg.tls_port.is_none() {
        return vec![Via::Direct];
    }
    match std::env::var("DREAMNAIL_DOOR").as_deref() {
        Ok("22") => return vec![Via::Direct],
        Ok("443") => return vec![Via::Tls],
        Ok("ws") => return vec![Via::Ws],
        _ => {}
    }
    // "Force 443" (user setting): skip port 22 entirely, go straight to the
    // 443 doors. The Reality fallback still applies after these if they fail.
    let mut order = if force_443() {
        vec![Via::Tls]
    } else {
        vec![Via::Direct, Via::Tls]
    };
    if cfg.ws_path.is_some() {
        order.push(Via::Ws);
    }
    // Float the last door that worked to the front (but never re-introduce port
    // 22 when the user asked to skip it).
    if let Some(pref) = read_door_pref() {
        if force_443() && pref == Via::Direct {
            return order;
        }
        if let Some(i) = order.iter().position(|v| *v == pref) {
            order.remove(i);
            order.insert(0, pref);
        }
    }
    order
}

fn door_pref_path() -> std::path::PathBuf {
    crate::xray::data_dir().join("door.pref")
}

/// Per-network door memory: the door that last worked on a SPECIFIC network,
/// keyed by a filesystem-safe form of `netid::current().id` (`wifi:<ssid>` /
/// `gw:<mac>`). So the first connect on a network you've used before tries the
/// door that worked there LAST time first — the school net goes straight to
/// whichever door gets through, instead of walking the ladder every time.
fn per_net_door_pref_path(key: &str) -> std::path::PathBuf {
    crate::xray::data_dir().join("doors").join(format!("{key}.pref"))
}

/// A filesystem-safe key for the network we're on now, or None when it's unknown
/// (offline, or the OS won't reveal the SSID) — then we fall back to the global
/// door pref. Best-effort + short-timeout inside `netid`, so this never hangs.
fn current_net_key() -> Option<String> {
    let id = crate::netid::current()?.id;
    let safe: String = id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '_' })
        .collect();
    (!safe.is_empty()).then_some(safe)
}

fn parse_via_tag(s: &str) -> Option<Via> {
    match s.trim() {
        "ws" => Some(Via::Ws),
        "443" => Some(Via::Tls),
        "22" => Some(Via::Direct),
        _ => None,
    }
}

fn read_door_pref() -> Option<Via> {
    // Network memory first: the door that last worked on THIS network. Fall back
    // to the global "last door that worked anywhere" when the network is unknown
    // or we've never succeeded here before.
    if let Some(key) = current_net_key() {
        if let Ok(s) = std::fs::read_to_string(per_net_door_pref_path(&key)) {
            if let Some(v) = parse_via_tag(&s) {
                return Some(v);
            }
        }
    }
    parse_via_tag(&std::fs::read_to_string(door_pref_path()).ok()?)
}

fn write_door_pref(via: Via) {
    let tag = match via {
        Via::Direct => "22",
        Via::Tls => "443",
        Via::Ws => "ws",
    };
    // Global fallback (unchanged behaviour for unknown networks).
    let p = door_pref_path();
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(&p, tag);
    // Per-network memory: remember this door won on this specific network.
    if let Some(key) = current_net_key() {
        let pn = per_net_door_pref_path(&key);
        if let Some(dir) = pn.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(pn, tag);
    }
}

// -- user setting: Force 443 (skip port 22) --------------------------------
// When on, the door ladder never tries port 22 — it goes straight to the 443
// doors (TLS → WebSocket), then the Reality fallback. For networks where 22 is
// blocked or the user just wants everything to look like HTTPS.

fn force_443_path() -> std::path::PathBuf {
    crate::xray::data_dir().join("force443.pref")
}

pub fn force_443() -> bool {
    if let Ok(v) = std::env::var("DREAMNAIL_FORCE_443") {
        return v == "1";
    }
    std::fs::read_to_string(force_443_path())
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

pub fn set_force_443(on: bool) {
    let p = force_443_path();
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(p, if on { "1" } else { "0" });
}

// ---- weak-network mode -----------------------------------------------------
// "Bad Wi-Fi mode": a single switch for jumpy / lossy networks. When on it
// (a) opens the maximum number of SSH stripes, (b) turns off browsing mux so
// every connection gets its own channel spread across them, and (c) races a
// new connection onto a second session sooner (150 ms vs 300 ms) when the
// first is slow to answer. Net effect: a lost packet on the air stalls one
// connection, not every tab. Read at connect time by `stripes()`,
// `hedge_after()` and `xray::browsing_mux()`; like the other
// prefs it lives in a plain sibling file so it survives a locked store, and
// `DREAMNAIL_WEAKNET=1|0` overrides.

fn weaknet_path() -> std::path::PathBuf {
    crate::xray::data_dir().join("weaknet.pref")
}

pub fn weaknet_mode() -> bool {
    if let Ok(v) = std::env::var("DREAMNAIL_WEAKNET") {
        return v == "1";
    }
    std::fs::read_to_string(weaknet_path())
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

pub fn set_weaknet_mode(on: bool) {
    let p = weaknet_path();
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(p, if on { "1" } else { "0" });
}

// -- user setting: Reality decoy site --------------------------------------
// Which real site the Reality door impersonates. The user picks the one their
// network allows; the server routes that site's name to a matching inbound.

fn reality_decoy_path() -> std::path::PathBuf {
    crate::xray::data_dir().join("reality_decoy.pref")
}

/// The chosen decoy SNI — the saved preference if it's a known decoy, else the
/// default (first in the list). `DREAMNAIL_REALITY_SNI` overrides (tests).
pub fn reality_decoy_sni() -> String {
    if let Ok(v) = std::env::var("DREAMNAIL_REALITY_SNI") {
        if crate::netcfg::is_known_decoy(&v) {
            return v;
        }
    }
    match std::fs::read_to_string(reality_decoy_path()) {
        Ok(s) if crate::netcfg::is_known_decoy(s.trim()) => s.trim().to_string(),
        _ => crate::netcfg::REALITY_SNI.to_string(),
    }
}

/// Save the chosen decoy SNI (ignored unless it's a known decoy).
pub fn set_reality_decoy(sni: &str) {
    if !crate::netcfg::is_known_decoy(sni) {
        return;
    }
    let p = reality_decoy_path();
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(p, sni);
}

/// Password auth on a handshaken session.
async fn authenticate(mut h: Handle<ClientHandler>, user: &str, pass: &str) -> Result<Session> {
    let auth = h
        .authenticate_password(user.to_owned(), pass.to_owned())
        .await
        .map_err(|e| EngineError::Tunnel(format!("{e:?}")))?;
    if !auth.success() {
        return Err(EngineError::Auth);
    }
    Ok(Arc::new(h))
}

/// One SSH connect + password auth.
async fn connect_session(
    config: Arc<Config>,
    cfg: &TunnelConfig,
    expected: Option<PublicKey>,
    user: &str,
    pass: &str,
) -> Result<Session> {
    authenticate(handshake(config, cfg, expected).await?, user, pass).await
}

/// Keep the web pool topped up to `want` live sessions while the main session
/// lives. Opens one at a time (the server limits parallel handshakes per IP)
/// and stops for good on an auth failure so it can never trip the server's
/// failed-login protections.
#[allow(clippy::too_many_arguments)]
async fn keep_stripes(
    pool: Arc<Pool>,
    main: Session,
    want: usize,
    config: Arc<Config>,
    cfg: TunnelConfig,
    expected: Option<PublicKey>,
    user: String,
    pass: String,
) {
    loop {
        if main.is_closed() {
            return;
        }
        if pool.live() < want {
            match connect_session(config.clone(), &cfg, expected.clone(), &user, &pass).await {
                Ok(h) => {
                    pool.add(h);
                    continue;
                }
                Err(EngineError::Auth) => return,
                Err(_) => tokio::time::sleep(Duration::from_secs(30)).await,
            }
        } else {
            tokio::time::sleep(Duration::from_secs(15)).await;
        }
    }
}

/// Bind a local TCP listener and pump each accepted connection over its own
/// SSH `direct-tcpip` channel to `remote_host:remote_port`, on a session picked
/// from `pool` (falling through to the next one if a channel can't be opened).
/// Returns the accept task so the caller can abort it on teardown. Used for
/// BOTH the primary VLESS forward and the optional udpgw forward, so the two
/// stay byte-for-byte identical in behaviour.
async fn spawn_forward(
    pool: Arc<Pool>,
    children: Arc<Mutex<Vec<JoinHandle<()>>>>,
    local_host: &str,
    local_port: u16,
    remote_host: String,
    remote_port: u16,
) -> Result<JoinHandle<()>> {
    let local: SocketAddr = format!("{local_host}:{local_port}")
        .parse()
        .map_err(|e| EngineError::Tunnel(format!("bad local addr: {e}")))?;
    // A fast disconnect→reconnect can race the previous listener's async close:
    // `close()` calls `task.abort()`, which is cooperative, so the old socket on
    // this loopback port may not be released the instant we rebind, yielding
    // "address already in use" (worst on Windows, which lacks SO_REUSEADDR). The
    // port frees within a few hundred ms, so retry a handful of times before
    // giving up rather than failing the whole reconnect.
    let listener = {
        let mut last: Option<std::io::Error> = None;
        let mut bound = None;
        for _ in 0..6 {
            match TcpListener::bind(local).await {
                Ok(l) => {
                    bound = Some(l);
                    break;
                }
                Err(e) => {
                    last = Some(e);
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
        match bound {
            Some(l) => l,
            None => {
                return Err(EngineError::Tunnel(format!(
                    "bind {local}: {}",
                    last.map(|e| e.to_string()).unwrap_or_default()
                )))
            }
        }
    };
    let rport = u32::from(remote_port);
    let lport = u32::from(local_port);
    // Web forward only: keep a few channels pre-opened (bad-Wi-Fi mode).
    let spares = pool.balanced.then(|| Arc::new(Spares::default()));
    if let Some(sp) = &spares {
        let keeper = tokio::spawn(keep_spares(pool.clone(), sp.clone(), remote_host.clone(), rport, lport));
        children.lock().unwrap_or_else(|e| e.into_inner()).push(keeper);
    }
    let task = tokio::spawn(async move {
        loop {
            let (inbound, _peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break, // listener closed on teardown
            };
            let rhost = remote_host.clone();
            let pool_child = pool.clone();
            let spare = spares.as_ref().and_then(|sp| sp.take());
            let child = tokio::spawn(async move {
                // A ready spare if there is one (instant); otherwise the
                // healthiest session, racing a second one if the first is slow
                // to answer (a stalled stream on jumpy Wi-Fi), falling through
                // the rest if sessions have died.
                let got = match spare {
                    Some(ok) => Some(ok),
                    None => open_best(pool_child.candidates(), &rhost, rport, lport).await,
                };
                if let Some((channel, won)) = got {
                    let _guard = ActiveGuard::new(won.active.clone());
                    let mut stream = channel.into_stream();
                    // Every tunnelled byte passes here (stealth/TUN included), so this
                    // is where the live throughput readout gets its numbers. Wrapping
                    // only the LOCAL end keeps the direction unambiguous: read = up.
                    let mut inbound = crate::traffic::Counted::new(inbound);
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut stream).await;
                    return;
                }
            });
            // Track this relay so close() can abort it; without that it keeps a
            // clone of its SSH session alive and the server never reaps it. Prune
            // finished ones here so the list can't grow without bound.
            {
                let mut c = children.lock().unwrap_or_else(|e| e.into_inner());
                c.retain(|t| !t.is_finished());
                c.push(child);
            }
        }
    });
    Ok(task)
}

impl Tunnel for RusshTunnel {
    fn open(&mut self, creds: &Credentials) -> Result<()> {
        if self.alive() {
            return Ok(()); // already up (SSH or Reality) — re-entrant bring-up is a no-op
        }
        // A CLOSED session (or a dead Reality marker) must not report success.
        // This is what made the watchdog's reconnect a silent no-op: after a drop
        // the handle is still Some (just dead), so `open()` returned Ok, Xray was
        // pointed at a forward that could never carry traffic, and the route probe
        // failed — turning every blip into a full disconnect. Drop the corpse and
        // build fresh instead.
        if self.handle.is_some() || self.reality || self.opened.load(Ordering::SeqCst) {
            self.close();
        }
        // Fresh attempt: default back to SSH mode until a door is chosen.
        set_reality_mode(false);
        self.reality = false;
        // DREAMNAIL_DOOR=reality forces the Reality door, skipping SSH entirely.
        if reality_enabled() && std::env::var("DREAMNAIL_DOOR").as_deref() == Ok("reality") {
            return self.engage_reality(creds);
        }
        let cfg = self.cfg.clone();
        let user = creds.username.clone();
        let pass = creds.password.clone();

        // Parse the pinned host key up front so a bad config is a clear error,
        // not a mid-connect surprise.
        let expected = match cfg.host_key.as_deref() {
            Some(s) if !s.is_empty() => Some(
                PublicKey::from_openssh(s)
                    .map_err(|e| EngineError::Tunnel(format!("bad pinned host key: {e}")))?,
            ),
            _ => None,
        };

        type BringUp = (
            Session,
            Option<Session>,
            Arc<Pool>,
            JoinHandle<()>,
            Option<JoinHandle<()>>,
            Option<JoinHandle<()>>,
        );
        let children = self.children.clone();
        let brought: Option<BringUp> = self.rt.block_on(async move {
            let config = Arc::new(Config {
                keepalive_interval: Some(cfg.keepalive),
                // ~3 missed keepalives → session closes. Weak-network mode
                // (lossy / bufferbloated links) tolerates 6 so one stall on
                // the main session doesn't force a full reconnect.
                keepalive_max: if weaknet_mode() { 6 } else { 3 },
                preferred: ssh_preferred(),
                nodelay: std::env::var("DREAMNAIL_SSH_NODELAY").map(|v| v != "0").unwrap_or(true),
                window_size: ssh_window(),
                ..Config::default()
            });

            // Main session + game lane (a second, independent SSH session for the
            // udpgw forward). Their handshakes run IN PARALLEL to save a round of
            // connect time, but the lane only sends the password AFTER the main
            // session's login succeeded — so a wrong password is still exactly one
            // failed login on the server (fail2ban / PerSourcePenalties).
            //
            // Door: the last one that worked first. If it can't be reached (port
            // 22 blocked on this network, say) the other is tried — the first
            // attempt gets a shorter timeout so a silently-dropped port doesn't
            // stall the button. Only a REACH failure moves on; a wrong password
            // is final (never a second failed login).
            let order = door_order(&cfg);
            let mut main_hs = None;
            let mut last_err = None;
            for (i, via) in order.iter().copied().enumerate() {
                let t = if i + 1 < order.len() {
                    cfg.connect_timeout.min(Duration::from_secs(5))
                } else {
                    cfg.connect_timeout
                };
                let lane_hs = async {
                    if cfg.udpgw_local_port.is_some() {
                        handshake_via(config.clone(), &cfg, expected.clone(), via, t).await.ok()
                    } else {
                        None
                    }
                };
                let main = handshake_via(config.clone(), &cfg, expected.clone(), via, t);
                let (m, l) = tokio::join!(main, lane_hs);
                match m {
                    Ok(h) => {
                        main_hs = Some((via, h, l));
                        break;
                    }
                    Err(e) => last_err = Some(e),
                }
            }
            let Some((via, main_h, lane_hs)) = main_hs else {
                // Every SSH door is unreachable. Signal the caller to try the
                // Reality door (or report the reach error if Reality is off).
                let _ = &last_err;
                return Ok(None);
            };
            let mut cfg = cfg;
            cfg.via = via;
            let handle = authenticate(main_h, &user, &pass).await?; // bad password fails the connect
            if order.len() > 1 && read_door_pref() != Some(via) {
                write_door_pref(via);
            }
            ACTIVE_PORT.store(
                if via == Via::Direct { cfg.port } else { cfg.tls_port.unwrap_or(443) },
                Ordering::Relaxed,
            );
            // Best-effort — if the lane can't be opened the udpgw forward rides
            // the main session exactly as before.
            let lane = match lane_hs {
                Some(h) => authenticate(h, &user, &pass).await.ok(),
                None => None,
            };

            // Primary forward: local VLESS port → server's loopback VLESS inbound,
            // striped across the web pool (just the main session until extras join).
            let web = Pool::new(vec![handle.clone()], true);
            let task = spawn_forward(
                web.clone(),
                children.clone(),
                &cfg.local_host,
                cfg.local_port,
                cfg.remote_host.clone(),
                cfg.remote_port,
            )
            .await?;

            // Optional udpgw forward: local udpgw port → server's loopback
            // udpgw-server, so UDP can be tunnelled over TCP (games/VoIP work on
            // macOS, where SOCKS UDP-associate is broken). Game lane first, main
            // session if the lane has died.
            let udpgw_task = match cfg.udpgw_local_port {
                Some(port) => {
                    let order: Vec<Session> = lane.iter().cloned().chain([handle.clone()]).collect();
                    Some(
                        spawn_forward(
                            Pool::new(order, false),
                            children.clone(),
                            &cfg.local_host,
                            port,
                            cfg.udpgw_remote_host.clone(),
                            cfg.udpgw_remote_port,
                        )
                        .await?,
                    )
                }
                None => None,
            };

            let want = stripes();
            let stripe_task = (want > 1).then(|| {
                tokio::spawn(keep_stripes(
                    web.clone(),
                    handle.clone(),
                    want,
                    config.clone(),
                    cfg.clone(),
                    expected.clone(),
                    user.clone(),
                    pass.clone(),
                ))
            });

            Ok::<Option<BringUp>, EngineError>(Some((handle, lane, web, task, udpgw_task, stripe_task)))
        })?;

        match brought {
            Some((handle, lane, web, task, udpgw_task, stripe_task)) => {
                self.handle = Some(handle);
                self.lane = lane;
                self.web = Some(web);
                self.accept_task = Some(task);
                self.udpgw_task = udpgw_task;
                self.stripe_task = stripe_task;
                self.reality = false;
                self.opened.store(true, Ordering::SeqCst);
                Ok(())
            }
            // SSH unreachable on every door → fall back to the Reality door.
            None if reality_enabled() => self.engage_reality(creds),
            None => Err(EngineError::Tunnel(
                "server unreachable on every door (22, 443)".into(),
            )),
        }
    }

    fn close(&mut self) {
        self.opened.store(false, Ordering::SeqCst);
        // Leave Reality mode so the next bring-up starts fresh on the SSH ladder.
        set_reality_mode(false);
        self.reality = false;
        if let Some(task) = self.stripe_task.take() {
            task.abort(); // stop opening extra stripes first
        }
        if let Some(task) = self.accept_task.take() {
            task.abort(); // stops accepting new local connections
        }
        if let Some(task) = self.udpgw_task.take() {
            task.abort(); // stop the udpgw forward too
        }
        // Abort every per-connection relay task so each releases its clone of the
        // SSH session. Without this a relay that's still copying keeps the session
        // referenced, its socket never closes, and the server keeps the stale
        // sshd-session alive (answering keepalives) — the pile-up that starved the
        // box's RAM. Must run before we drop/disconnect the sessions below.
        for t in std::mem::take(&mut *self.children.lock().unwrap_or_else(|e| e.into_inner())) {
            t.abort();
        }
        // Extra stripes + game lane + main session. Best-effort clean
        // disconnects; dropping the handles closes them anyway.
        let mut sessions: Vec<Session> = self.web.take().map(|p| p.drain()).unwrap_or_default();
        sessions.extend(self.lane.take());
        if let Some(main) = self.handle.take() {
            sessions.retain(|s| !Arc::ptr_eq(s, &main));
            sessions.push(main);
        }
        self.rt.block_on(async move {
            for s in sessions {
                // Bounded: on a dead socket with a full outbound queue the send
                // can block forever, freezing the engine thread (no watchdog, no
                // proxy restore). Dropping the handle closes it regardless.
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(500),
                    s.disconnect(russh::Disconnect::ByApplication, "", "en"),
                )
                .await;
            }
        });
    }

    fn alive(&self) -> bool {
        // In Reality mode there is no SSH session — liveness rests on Xray, which
        // the engine checks separately, so the tunnel marker just reports opened.
        self.opened.load(Ordering::SeqCst)
            && (self.reality || self.handle.as_ref().is_some_and(|h| !h.is_closed()))
    }
}

impl Drop for RusshTunnel {
    /// Safety net: if a tunnel is ever dropped without an explicit `close()` (the
    /// engine being replaced, app shutdown, or a future reconnect path that
    /// forgets to tear down), still abort its relay tasks and disconnect its SSH
    /// sessions so the server reaps them instead of leaking stale tunnels.
    fn drop(&mut self) {
        if self.opened.load(Ordering::SeqCst) || self.handle.is_some() || self.web.is_some() {
            self.close();
        }
    }
}

#[cfg(test)]
mod health_tests {
    use super::*;

    #[test]
    fn stuck_session_scores_worse_than_busy_healthy_one() {
        let healthy = Health::new();
        healthy.record(20);
        let stuck = Health::new();
        stuck.record(20);
        stuck.pending.fetch_add(1, Ordering::Relaxed); // an open is hanging
        // 10 open channels on a healthy session still beat one hung open.
        assert!(healthy.score(10) < stuck.score(0));
    }

    #[test]
    fn slow_opens_raise_the_score_and_recover() {
        let h = Health::new();
        h.record(20);
        let base = h.score(0);
        h.record(2000);
        assert!(h.score(0) > base + 400);
        for _ in 0..12 {
            h.record(20);
        }
        assert!(h.score(0) < 60, "recovers once opens are fast again");
    }

    #[test]
    fn hedge_delay_follows_bad_wifi_mode() {
        std::env::remove_var("DREAMNAIL_HEDGE_MS");
        std::env::set_var("DREAMNAIL_WEAKNET", "1");
        assert_eq!(hedge_after(), Some(Duration::from_millis(150)));
        std::env::set_var("DREAMNAIL_WEAKNET", "0");
        assert_eq!(hedge_after(), Some(Duration::from_millis(300)));
        std::env::set_var("DREAMNAIL_HEDGE_MS", "0");
        assert_eq!(hedge_after(), None);
        std::env::remove_var("DREAMNAIL_HEDGE_MS");
        // Spare channels: only in bad-Wi-Fi mode (normal mode has mux).
        std::env::remove_var("DREAMNAIL_SPARES");
        assert_eq!(spare_target(), 0);
        std::env::set_var("DREAMNAIL_WEAKNET", "1");
        assert_eq!(spare_target(), 6);
        std::env::set_var("DREAMNAIL_SPARES", "99");
        assert_eq!(spare_target(), 16);
        std::env::remove_var("DREAMNAIL_SPARES");
        std::env::remove_var("DREAMNAIL_WEAKNET");
    }
}
