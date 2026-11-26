//! Remote access to THIS device (operator opt-in) — a second, locked-down SSH
//! connection that lets the owner reach their own machine from their server.
//!
//! What it does, in plain terms: when the owner turns "Remote access to this
//! device" on in Settings AND the VPN is connected, the app opens a *separate*
//! SSH connection to the Dreamnail server and asks the server to publish this
//! machine's own SSH (127.0.0.1:22) on a loopback-only port on the server. The
//! owner then SSHes into their server (which only they hold the key for) and
//! hops to that port to land on this machine. Nothing is exposed to the public
//! internet, and the link exists only while the toggle is on.
//!
//! Why it is safe:
//!   * OFF by default. It never runs unless the owner turns it on.
//!   * NOT shipped to customers. The server account + the private key that this
//!     feature needs live in two files on disk (`remote_access.key` and
//!     `remote_access.id`) that only exist on machines the operator provisions
//!     by hand. No file → `provisioned()` is false → the toggle does nothing.
//!     No key is baked into any build, so a customer's copy can never reach the
//!     operator's machines.
//!   * The server account is restricted (sshd `Match`: `PermitListen` only the
//!     one assigned loopback port, `PermitOpen none`, no TTY, forced
//!     `/usr/sbin/nologin`), so even if the key leaked it could only bind that
//!     loopback port — and still hit this machine's own SSH login behind it.
//!   * The connection rides the already-working VPN path (through the local
//!     SOCKS proxy out to the server), so it reaches the server on whatever
//!     door the tunnel found — no need for port 22 to be open on the owner's
//!     network, and the server's host key is pinned exactly as the tunnel pins
//!     it.
//!
//! Files (all under `data_dir()`):
//!   * `remote_access.pref`  — "on"/"off", the Settings toggle.
//!   * `remote_access.key`   — OpenSSH private key for the server account.
//!   * `remote_access.id`    — two lines: the server username, then the
//!                             assigned loopback port on the server.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use russh::client::{self, Config, Handle};
use russh::keys::{load_secret_key, PrivateKeyWithHashAlg};
use russh::keys::{HashAlg, PublicKey, PublicKeyOrCertificate};
use russh::Channel;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;

use crate::netcfg;

/// The owner turned remote access on. Read fresh from disk so it survives a
/// locked store, same as the other device prefs. `DREAMNAIL_REMOTE_ACCESS=1|0`
/// overrides (tests / headless).
#[must_use]
pub fn enabled() -> bool {
    if let Ok(v) = std::env::var("DREAMNAIL_REMOTE_ACCESS") {
        return v == "1";
    }
    std::fs::read_to_string(pref_path())
        .map(|s| s.trim() == "on")
        .unwrap_or(false)
}

/// Persist the Settings toggle. Turning it off also tears any live link down on
/// the next `ensure` tick.
pub fn set_enabled(on: bool) {
    let p = pref_path();
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(p, if on { "on" } else { "off" });
}

/// True when this machine has been provisioned for remote access (both the
/// private key and the id file are present). The UI uses this to show the
/// toggle only where it can actually work.
#[must_use]
pub fn provisioned() -> bool {
    key_path().is_file() && read_id().is_some()
}

fn pref_path() -> std::path::PathBuf {
    crate::xray::data_dir().join("remote_access.pref")
}
fn key_path() -> std::path::PathBuf {
    crate::xray::data_dir().join("remote_access.key")
}
fn id_path() -> std::path::PathBuf {
    crate::xray::data_dir().join("remote_access.id")
}

/// (server username, assigned loopback port) from `remote_access.id`, or None if
/// the file is missing or malformed.
fn read_id() -> Option<(String, u16)> {
    let text = std::fs::read_to_string(id_path()).ok()?;
    let mut lines = text.lines();
    let user = lines.next()?.trim().to_string();
    let port: u16 = lines.next()?.trim().parse().ok()?;
    if user.is_empty() || port == 0 {
        return None;
    }
    Some((user, port))
}

// ---- controller ----------------------------------------------------------

static RUNNING: AtomicBool = AtomicBool::new(false);
static STOP: AtomicBool = AtomicBool::new(false);

struct Ctl {
    rt: Runtime,
    task: Option<tokio::task::JoinHandle<()>>,
}

fn ctl() -> &'static Mutex<Option<Ctl>> {
    static C: OnceLock<Mutex<Option<Ctl>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}

/// Idempotent controller, called from the watchdog tick. Starts the remote
/// link when (enabled && provisioned && connected) and stops it otherwise. Safe
/// to call every tick; it only acts on an actual change.
pub fn ensure(connected: bool) {
    let want = connected && enabled() && provisioned();
    if want == RUNNING.load(Ordering::SeqCst) {
        return;
    }
    let mut guard = ctl().lock().unwrap_or_else(|e| e.into_inner());
    if want {
        let Some((user, port)) = read_id() else { return };
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(_) => return,
        };
        STOP.store(false, Ordering::SeqCst);
        RUNNING.store(true, Ordering::SeqCst);
        let task = rt.spawn(run_loop(user, port));
        *guard = Some(Ctl { rt, task: Some(task) });
    } else {
        STOP.store(true, Ordering::SeqCst);
        if let Some(mut c) = guard.take() {
            if let Some(t) = c.task.take() {
                t.abort();
            }
            // Drop the runtime without blocking the watchdog thread.
            c.rt.shutdown_background();
        }
        RUNNING.store(false, Ordering::SeqCst);
    }
}

/// Whether a reverse link is currently live (for status / the UI).
#[must_use]
pub fn is_live() -> bool {
    RUNNING.load(Ordering::SeqCst)
}

/// Reconnecting supervisor: keep one reverse link alive while we're wanted.
async fn run_loop(user: String, port: u16) {
    let mut backoff = Duration::from_secs(2);
    while !STOP.load(Ordering::SeqCst) {
        match serve_once(&user, port).await {
            Ok(()) => backoff = Duration::from_secs(2), // clean end → quick retry
            Err(_) => {
                // Patchy link / server blip. Back off, capped, and try again.
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }
    }
}

/// One connect → publish this machine's SSH on the server → pump until the
/// session ends. Returns Ok when the session closed cleanly, Err on any
/// connect/auth/transport failure (the caller backs off and retries).
async fn serve_once(user: &str, port: u16) -> std::result::Result<(), String> {
    // Reach the server over the working VPN path (local SOCKS → server:22), so
    // this needs no open port on the owner's network beyond what the VPN already
    // uses. `DREAMNAIL_REMOTE_DIRECT=1` connects straight to the server instead
    // (used to provision/verify on a network where port 22 is open; the key gate
    // is unchanged either way).
    let stream = if std::env::var("DREAMNAIL_REMOTE_DIRECT").as_deref() == Ok("1") {
        TcpStream::connect((netcfg::EXPECTED_EXIT_IP, 22u16))
            .await
            .map_err(|e| format!("direct: {e}"))?
    } else {
        socks5_connect(netcfg::EXPECTED_EXIT_IP, 22)
            .await
            .map_err(|e| format!("socks: {e}"))?
    };

    let expected = PublicKey::from_openssh(crate::tunnel::server_host_key())
        .map_err(|e| format!("pin: {e}"))?;
    let config = Arc::new(Config {
        keepalive_interval: Some(Duration::from_secs(15)),
        keepalive_max: 3,
        ..Config::default()
    });
    let mut handle: Handle<RemoteHandler> =
        client::connect_stream(config, stream, RemoteHandler { expected })
            .await
            .map_err(|e| format!("ssh: {e:?}"))?;

    let key = load_secret_key(key_path(), None).map_err(|e| format!("key: {e:?}"))?;
    let auth = handle
        .authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), None))
        .await
        .map_err(|e| format!("auth: {e:?}"))?;
    if !auth.success() {
        return Err("auth rejected".into());
    }

    // Ask the server to listen on its loopback and forward back to us. Incoming
    // connections arrive as forwarded-tcpip channels, handled below.
    handle
        .tcpip_forward("127.0.0.1", u32::from(port))
        .await
        .map_err(|e| format!("forward: {e:?}"))?;

    // Hold the session open until it dies. The handler does the real work when
    // the server opens forwarded channels; here we just wait for the transport
    // to end or for a stop request.
    loop {
        if STOP.load(Ordering::SeqCst) {
            let _ = handle.cancel_tcpip_forward("127.0.0.1", u32::from(port)).await;
            let _ = handle
                .disconnect(russh::Disconnect::ByApplication, "", "en")
                .await;
            return Ok(());
        }
        // Cheap liveness check: a disconnected transport makes this error out.
        if handle
            .send_keepalive(false)
            .await
            .is_err()
        {
            return Ok(()); // session gone — supervisor reconnects
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// Minimal SOCKS5 CONNECT (no auth) to the local VLESS proxy, targeting
/// `host:port` out on the server side. Returns the connected stream.
async fn socks5_connect(host: &str, port: u16) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect((netcfg::SOCKS_HOST, netcfg::SOCKS_PORT)).await?;
    // greeting: VER=5, 1 method, 0=no-auth
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut rep = [0u8; 2];
    s.read_exact(&mut rep).await?;
    if rep != [0x05, 0x00] {
        return Err(std::io::Error::other("socks: no-auth refused"));
    }
    // CONNECT, ATYP=domain (works for an IP literal too, and keeps it simple)
    let host_b = host.as_bytes();
    if host_b.len() > 255 {
        return Err(std::io::Error::other("socks: host too long"));
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host_b.len() as u8];
    req.extend_from_slice(host_b);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;
    // reply: VER REP RSV ATYP + BND.ADDR + BND.PORT
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        return Err(std::io::Error::other(format!("socks: reply {}", head[1])));
    }
    let skip = match head[3] {
        0x01 => 4 + 2,                                   // IPv4 + port
        0x04 => 16 + 2,                                  // IPv6 + port
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize + 2
        }
        _ => return Err(std::io::Error::other("socks: bad ATYP")),
    };
    let mut junk = vec![0u8; skip];
    s.read_exact(&mut junk).await?;
    Ok(s)
}

// ---- SSH client handler --------------------------------------------------

struct RemoteHandler {
    expected: PublicKey,
}

impl client::Handler for RemoteHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => {
                Ok(key.fingerprint(HashAlg::Sha256) == self.expected.fingerprint(HashAlg::Sha256))
            }
            PublicKeyOrCertificate::Certificate(_) => Ok(false),
        }
    }

    /// The server opened a connection back to us (someone is reaching this
    /// machine through the server's loopback port). Pipe it to our own SSH.
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<client::Msg>,
        _connected_address: &str,
        _connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        reply.accept().await;
        tokio::spawn(pipe_to_local_ssh(channel));
        Ok(())
    }
}

/// Splice one forwarded channel to this machine's own SSH daemon (127.0.0.1:22).
async fn pipe_to_local_ssh(channel: Channel<client::Msg>) {
    let Ok(local) = TcpStream::connect(("127.0.0.1", 22u16)).await else {
        // No local SSH server running → nothing to reach. Drop the channel.
        let _ = channel.close().await;
        return;
    };
    let (mut lr, mut lw) = local.into_split();
    let mut stream = channel.into_stream();
    let (mut sr, mut sw) = tokio::io::split(&mut stream);
    let up = async {
        let _ = tokio::io::copy(&mut lr, &mut sw).await;
        let _ = sw.shutdown().await;
    };
    let down = async {
        let _ = tokio::io::copy(&mut sr, &mut lw).await;
        let _ = lw.shutdown().await;
    };
    tokio::join!(up, down);
}
