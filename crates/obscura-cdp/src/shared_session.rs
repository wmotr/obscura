//! Opt-in shared CDP session (`obscura serve --shared-session`).
//!
//! The default server gives every WebSocket its own `cdp_processor`, its own
//! `CdpContext` and its own pages (#430, #449). That is the right isolation for
//! independent clients, but it means two connections can never see the same
//! document: a browser harness and a credential-vault supervisor that both
//! drive one task open two sockets and get two blank browsers.
//!
//! This mode keeps ONE `cdp_processor` on ONE OS thread (V8 still has a single
//! owner, so the one-entered-isolate-per-thread invariant is untouched) and
//! lets several *authorized* WebSockets multiplex commands into it:
//!
//! - every response goes back to the client that sent the command;
//! - events are broadcast to every attached client (documented limitation);
//! - pages, sessions and the cookie jar live in the processor and survive a
//!   client disconnect, so a reconnect picks the same document back up;
//! - one server process is one shared session. Run one process per task.
//!
//! Because the session is process-wide, it is only reachable with a bearer
//! token, only on a loopback address, and a browser page cannot drive-by it:
//! WS upgrades carrying an `Origin` header are refused.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Notify};
use tokio_tungstenite::tungstenite::Message;
use tracing::{error, info, warn};

use crate::dispatch::CdpContext;
use crate::server::{
    cdp_processor_with_ctx, fast_path_response, CdpMessage, ReplyTx, ServerMessage, SharedClient,
};
use crate::types::CdpRequest;

/// Default cap on concurrently attached shared-session clients. Each client is
/// one socket and one queue, not a thread and not an isolate, so this can be
/// far below `DEFAULT_MAX_CONNECTIONS`; a task needs a handful at most.
pub const DEFAULT_MAX_SHARED_CLIENTS: usize = 16;

/// Shortest accepted bearer token. Hermes generates its own token; 32 characters
/// is the floor we refuse to go under, not a recommendation.
pub const MIN_SESSION_TOKEN_LEN: usize = 32;

// Leave room for the URL and normal headers inside the bounded request head.
const MAX_SESSION_TOKEN_LEN: usize = 256;

/// Outbound queue per client: events plus responses. When it fills the client
/// is not keeping up, and it is disconnected instead of buffering without bound.
const SHARED_CLIENT_QUEUE: usize = 256;
/// Inbound command queue shared by all attached clients. Bounded so a client
/// that spams commands cannot grow the process; `send` backpressures its own
/// reader, leaving other clients' sockets readable.
const SHARED_COMMAND_QUEUE: usize = 512;
const SHARED_HANDOFF_QUEUE: usize = 64;
const MAX_WS_WRITE_BUFFER: usize = 8 << 20;

const HTTP_PEEK_BUF: usize = 4096;
const SILENT_CONNECTION_TTL: std::time::Duration = std::time::Duration::from_secs(10);
const ACCEPT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(1);
const MAX_SILENT_PENDING: usize = 64;

/// Bearer token for the shared session.
///
/// Deliberately opaque: `Debug` is redacted so a token cannot reach a log line
/// through a `{:?}` on a config or a request struct.
#[derive(Clone)]
pub struct SessionToken {
    secret: Arc<str>,
}

impl SessionToken {
    /// Build a token from an in-memory secret. Prefer [`SessionToken::from_file`]
    /// from a CLI so the secret is never on a command line.
    pub fn new(secret: &str) -> anyhow::Result<Self> {
        validate_secret(secret)?;
        Ok(Self {
            secret: Arc::from(secret),
        })
    }

    /// Read a token from `path`, refusing any file a process other than its
    /// owner can read or write.
    ///
    /// The permission check runs on the opened file's metadata rather than on
    /// a path lookup, so a symlink swapped in after the check cannot hand us a
    /// different file.
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(all(unix, target_env = "gnu"))]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options.open(path).map_err(|e| {
            anyhow::anyhow!("cannot open session token file {}: {}", path.display(), e)
        })?;
        let metadata = file.metadata().map_err(|e| {
            anyhow::anyhow!(
                "cannot stat session token file {}: {}",
                path.display(),
                e
            )
        })?;
        if !metadata.is_file() {
            anyhow::bail!(
                "session token file {} is not a regular file",
                path.display()
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                anyhow::bail!(
                    "session token file {} has mode {:03o}; group/other access is refused, use chmod 600",
                    path.display(),
                    mode
                );
            }
        }
        let mut raw = String::new();
        let mut reader = std::io::BufReader::new(file).take((MAX_SESSION_TOKEN_LEN + 1) as u64);
        reader.read_to_string(&mut raw).map_err(|e| {
            anyhow::anyhow!(
                "cannot read session token file {}: {}",
                path.display(),
                e
            )
        })?;
        if raw.len() > MAX_SESSION_TOKEN_LEN {
            anyhow::bail!(
                "session token file {} is larger than {} bytes",
                path.display(),
                MAX_SESSION_TOKEN_LEN
            );
        }
        // A trailing newline from `echo`/`openssl rand` is expected; nothing else
        // may be trimmed away, or two different files could yield one token.
        Self::new(raw.trim_end_matches(['\r', '\n'])).map_err(|e| {
            anyhow::anyhow!("session token file {}: {}", path.display(), e)
        })
    }

    /// Constant-time comparison against a candidate the client supplied.
    pub fn matches(&self, candidate: &str) -> bool {
        constant_time_eq(self.secret.as_bytes(), candidate.as_bytes())
    }

    fn as_str(&self) -> &str {
        &self.secret
    }
}

impl std::fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionToken(<redacted>)")
    }
}

fn validate_secret(secret: &str) -> anyhow::Result<()> {
    if secret.len() < MIN_SESSION_TOKEN_LEN {
        anyhow::bail!(
            "session token must be at least {} characters",
            MIN_SESSION_TOKEN_LEN
        );
    }
    if secret.len() > MAX_SESSION_TOKEN_LEN {
        anyhow::bail!(
            "session token must be at most {} characters",
            MAX_SESSION_TOKEN_LEN
        );
    }
    // Keep the token usable verbatim as a URL query value and as a bearer
    // credential: URL-safe characters only, no separators that would need
    // escaping and no whitespace or control characters.
    let valid = secret.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
    });
    if !valid {
        anyhow::bail!(
            "session token may only contain [A-Za-z0-9._~-] characters"
        );
    }
    Ok(())
}

/// Compare two byte strings without an early exit on the first differing byte,
/// so a wrong token cannot be guessed one character at a time from timing.
fn constant_time_eq(expected: &[u8], candidate: &[u8]) -> bool {
    if expected.len() != candidate.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in expected.iter().zip(candidate.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

/// Configuration for the shared session server.
#[derive(Debug, Clone)]
pub struct SharedSessionConfig {
    port: u16,
    host: String,
    token: SessionToken,
    proxy: Option<String>,
    stealth: bool,
    user_agent: Option<String>,
    allow_file_access: bool,
    allow_private_network: bool,
    max_clients: usize,
}

impl SharedSessionConfig {
    /// Loopback-only configuration. A non-loopback `host` is refused here as
    /// well as in the CLI: authentication is the second line of defence, not
    /// the only one, and a shared session must never be reachable off-host.
    pub fn new(port: u16, host: &str, token: SessionToken) -> anyhow::Result<Self> {
        let ip: IpAddr = host
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid --host '{}': {} (shared sessions require a literal loopback IP)", host, e))?;
        if !ip.is_loopback() {
            anyhow::bail!(
                "--shared-session only binds a loopback address; refusing --host '{}'",
                host
            );
        }
        Ok(Self {
            port,
            host: host.to_string(),
            token,
            proxy: None,
            stealth: false,
            user_agent: None,
            allow_file_access: false,
            allow_private_network: false,
            max_clients: DEFAULT_MAX_SHARED_CLIENTS,
        })
    }

    /// Full constructor used by the CLI: token from a file, everything else
    /// from flags.
    #[allow(clippy::too_many_arguments)]
    pub fn from_token_file(
        port: u16,
        host: &str,
        token_file: &Path,
        proxy: Option<String>,
        stealth: bool,
        user_agent: Option<String>,
        allow_file_access: bool,
        allow_private_network: bool,
        max_clients: usize,
    ) -> anyhow::Result<Self> {
        let token = SessionToken::from_file(token_file)?;
        let mut config = Self::new(port, host, token)?;
        config.proxy = proxy;
        config.stealth = stealth;
        config.user_agent = user_agent;
        config.allow_file_access = allow_file_access;
        config.allow_private_network = allow_private_network;
        config.max_clients = max_clients.max(1);
        Ok(config)
    }

    pub fn with_network(mut self, proxy: Option<String>, stealth: bool, user_agent: Option<String>) -> Self {
        self.proxy = proxy;
        self.stealth = stealth;
        self.user_agent = user_agent;
        self
    }

    pub fn with_file_access(mut self, allow: bool) -> Self {
        self.allow_file_access = allow;
        self
    }

    pub fn with_private_network(mut self, allow: bool) -> Self {
        self.allow_private_network = allow;
        self
    }

    pub fn with_max_clients(mut self, max_clients: usize) -> Self {
        self.max_clients = max_clients.max(1);
        self
    }

    pub fn addr(&self) -> SocketAddr {
        // `new` refused anything that did not parse as a loopback IpAddr.
        let ip: IpAddr = self
            .host
            .parse()
            .expect("shared session host validated in SharedSessionConfig::new");
        SocketAddr::new(ip, self.port)
    }
}

/// A WebSocket that passed authentication and is waiting for the session thread
/// to pick it up.
struct Handoff {
    stream: std::net::TcpStream,
    client_id: u64,
    live_clients: Arc<AtomicUsize>,
}

/// Releases the `max_clients` slot however the connection task exits.
struct SlotGuard(Arc<AtomicUsize>);

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Run the shared session until the process is asked to stop.
///
/// One OS thread owns the single `cdp_processor` (and therefore every V8
/// isolate); a second one accepts sockets, serves authenticated discovery and
/// hands authenticated upgrades over. Keeping the accept path off the session
/// thread is what lets `/json/version` answer while a page is blocked in V8.
pub async fn start_shared_session(config: SharedSessionConfig) -> anyhow::Result<()> {
    let addr = config.addr();
    let host = config.host.clone();
    let max_clients = config.max_clients;
    let token = config.token.clone();

    let std_listener = std::net::TcpListener::bind(addr)
        .map_err(|e| anyhow::anyhow!("bind {}: {}", addr, e))?;
    let port = std_listener.local_addr()?.port();
    std_listener
        .set_nonblocking(true)
        .map_err(|e| anyhow::anyhow!("set_nonblocking: {}", e))?;

    // No token, no URI in this line: the token must not reach a log sink.
    info!(
        "Obscura shared CDP session listening on ws://{}:{}/devtools/browser \
         (loopback only, bearer token required)",
        host, port
    );
    if config.allow_file_access {
        info!("file:// navigation enabled (--allow-file-access) in the shared session.");
    }

    let (handoff_tx, handoff_rx) = mpsc::channel::<Handoff>(SHARED_HANDOFF_QUEUE);
    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let shutdown_notify = Arc::new(Notify::new());
    spawn_shutdown_watcher(shutdown_flag.clone(), shutdown_notify.clone());

    // V8's process-global isolate tables must be initialized once on the main
    // thread before any other thread creates an isolate (#430).
    drop(obscura_js::runtime::ObscuraJsRuntime::new());

    let live_clients = Arc::new(AtomicUsize::new(0));
    let accept_state = Arc::new(AcceptState {
        port,
        host,
        token,
        max_clients,
        live_clients: live_clients.clone(),
        next_client_id: Arc::new(AtomicU64::new(1)),
        handoff_tx,
        shutdown: shutdown_flag.clone(),
    });
    std::thread::Builder::new()
        .name("obscura-cdp-shared-accept".into())
        .spawn(move || accept_loop(std_listener, accept_state))?;

    let (done_tx, done_rx) = oneshot::channel::<()>();
    std::thread::Builder::new()
        .name("obscura-cdp-session".into())
        .spawn(move || run_session_thread(config, handoff_rx, shutdown_notify, done_tx))?;

    // `start_*` returns when the server stops, like the default serve path. The
    // wait is async so an embedding async runtime is not blocked by the join.
    let _ = done_rx.await;
    Ok(())
}

/// Ctrl-C / SIGTERM watcher, on its own thread so it needs no LocalSet and
/// cannot be starved by a page that is blocked inside V8.
fn spawn_shutdown_watcher(shutdown_flag: Arc<AtomicBool>, shutdown_notify: Arc<Notify>) {
    std::thread::Builder::new()
        .name("obscura-cdp-shared-signal".into())
        .spawn(move || {
            if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                rt.block_on(async {
                    #[cfg(unix)]
                    {
                        use tokio::signal::unix::{signal, SignalKind};
                        match signal(SignalKind::terminate()) {
                            Ok(mut term) => {
                                tokio::select! {
                                    _ = tokio::signal::ctrl_c() => {}
                                    _ = term.recv() => {}
                                }
                            }
                            Err(_) => {
                                let _ = tokio::signal::ctrl_c().await;
                            }
                        }
                    }
                    #[cfg(not(unix))]
                    {
                        let _ = tokio::signal::ctrl_c().await;
                    }
                });
            }
            shutdown_flag.store(true, Ordering::Relaxed);
            shutdown_notify.notify_waiters();
        })
        .ok();
}

/// The session thread: one shared `CdpContext`, one processor, one LocalSet.
fn run_session_thread(
    config: SharedSessionConfig,
    mut handoff_rx: mpsc::Receiver<Handoff>,
    shutdown_notify: Arc<Notify>,
    done: oneshot::Sender<()>,
) {
    let mut browser_context = obscura_browser::BrowserContext::with_storage_and_network(
        "default".to_string(),
        config.proxy.clone(),
        config.stealth,
        config.user_agent.clone(),
        // No storage dir: see `SharedSessionConfig`. Cookies live in memory for
        // the lifetime of the process and are never written to disk unencrypted.
        None,
        config.allow_private_network,
    );
    browser_context.allow_file_access = config.allow_file_access;

    let mut ctx = CdpContext::new_with_shared_context(Arc::new(browser_context));
    // One blank page with a deterministic session id, so a reconnecting client
    // can address the shared document without replaying Target.createTarget.
    let page_id = ctx.create_page();
    let default_session_id = format!("{page_id}-session");
    ctx.sessions.insert(default_session_id.clone(), page_id.clone());

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!("shared session runtime build failed: {}", e);
            let _ = done.send(());
            return;
        }
    };
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async move {
        let (msg_tx, msg_rx) = mpsc::channel::<ServerMessage>(SHARED_COMMAND_QUEUE);
        // Held for the lifetime of the loop: dropping every sender would end the
        // processor's `recv` and exit before the server stops.
        let keepalive = msg_tx.clone();
        let processor =
            tokio::task::spawn_local(cdp_processor_with_ctx(msg_rx, ctx, shutdown_notify.clone()));

        loop {
            tokio::select! {
                handoff = handoff_rx.recv() => match handoff {
                    Some(handoff) => {
                        tokio::task::spawn_local(handle_shared_connection(handoff, msg_tx.clone()));
                    }
                    None => break,
                },
                _ = shutdown_notify.notified() => {
                    info!("Shutdown signal received (shared session)");
                    break;
                }
            }
        }

        drop(keepalive);
        processor.abort();
        let _ = processor.await;
    });
    let _ = done.send(());
}

struct AcceptState {
    port: u16,
    host: String,
    token: SessionToken,
    max_clients: usize,
    live_clients: Arc<AtomicUsize>,
    next_client_id: Arc<AtomicU64>,
    handoff_tx: mpsc::Sender<Handoff>,
    shutdown: Arc<AtomicBool>,
}

/// Accept thread: same shape as the default server's (park silent sockets, never
/// block on a stream), plus authentication before anything is handed over.
fn accept_loop(listener: std::net::TcpListener, state: Arc<AcceptState>) {
    let mut pending: Vec<(std::net::TcpStream, std::time::Instant)> = Vec::new();
    while !state.shutdown.load(Ordering::Relaxed) {
        if pending.is_empty() {
            let _ = listener.set_nonblocking(false);
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(true);
                    pending.push((stream, std::time::Instant::now()));
                }
                Err(e) => {
                    error!("Accept error: {}", e);
                    std::thread::sleep(ACCEPT_POLL_INTERVAL);
                }
            }
            let _ = listener.set_nonblocking(true);
        } else {
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = stream.set_nonblocking(true);
                        if pending.len() < MAX_SILENT_PENDING {
                            pending.push((stream, std::time::Instant::now()));
                        } else {
                            warn!(
                                "shared session: dropping connection, {} parked without a request head",
                                MAX_SILENT_PENDING
                            );
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        error!("Accept error: {}", e);
                        break;
                    }
                }
            }
        }

        for (stream, since) in std::mem::take(&mut pending) {
            if since.elapsed() >= SILENT_CONNECTION_TTL {
                continue;
            }
            match peek_request_head(&stream) {
                PeekStatus::NotReady => pending.push((stream, since)),
                PeekStatus::Closed => {}
                PeekStatus::Head(head) => {
                    // Never log the request target: it carries the token.
                    if let Err(e) = dispatch_request(stream, &state, &head) {
                        let message = e.to_string();
                        if !message.contains("close") {
                            error!("shared session: request dispatch failed: {}", message);
                        }
                    }
                }
            }
        }
        if !pending.is_empty() {
            std::thread::sleep(ACCEPT_POLL_INTERVAL);
        }
    }
}

enum PeekStatus {
    NotReady,
    Closed,
    Head(String),
}

fn peek_request_head(stream: &std::net::TcpStream) -> PeekStatus {
    let mut buf = [0u8; HTTP_PEEK_BUF];
    let n = match stream.peek(&mut buf) {
        Ok(0) => return PeekStatus::Closed,
        Ok(n) => n,
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return PeekStatus::NotReady,
        Err(_) => return PeekStatus::Closed,
    };
    let head = &buf[..n];
    if n >= 4 && head[..4] != *b"GET " {
        return PeekStatus::Head(String::from_utf8_lossy(head).into_owned());
    }
    let complete = n == HTTP_PEEK_BUF || head.windows(4).any(|w| w == b"\r\n\r\n");
    if !complete {
        return PeekStatus::NotReady;
    }
    PeekStatus::Head(String::from_utf8_lossy(head).into_owned())
}

/// A parsed request head. Only what authentication and routing need; the body is
/// irrelevant for both HTTP endpoints and the WebSocket upgrade.
struct RequestHead<'a> {
    method: &'a str,
    path: &'a str,
    query: Option<&'a str>,
    headers: Vec<(&'a str, &'a str)>,
}

fn parse_request_head(head: &str) -> Option<RequestHead<'_>> {
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split(' ').filter(|part| !part.is_empty());
    let method = parts.next()?;
    let target = parts.next()?;
    if !target.starts_with('/') {
        // Absolute-form or garbage: refuse rather than guess a path from it.
        return None;
    }
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    };
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim(), value.trim()));
        }
    }
    Some(RequestHead {
        method,
        path,
        query,
        headers,
    })
}

impl RequestHead<'_> {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| *value)
    }

    /// Token from `Authorization: Bearer <token>` or `?token=<token>`, in that
    /// order. Hermes puts it in the CDP URL's query string; a client that
    /// prefers a header is not forced to build the URL with it.
    fn supplied_token(&self) -> Option<String> {
        if let Some(value) = self.header("authorization") {
            let value = value.trim();
            for prefix in ["Bearer ", "bearer "] {
                if let Some(token) = value.strip_prefix(prefix) {
                    return Some(token.trim().to_string());
                }
            }
        }
        let query = self.query?;
        url::form_urlencoded::parse(query.as_bytes())
            .find(|(key, _)| key == "token")
            .map(|(_, value)| value.into_owned())
    }
}

fn is_websocket_path(path: &str) -> bool {
    path == "/devtools/browser" || path.starts_with("/devtools/page/")
}

fn write_http_response(
    mut stream: std::net::TcpStream,
    status: &str,
    extra_headers: &[(&str, &str)],
    body: &str,
) -> anyhow::Result<()> {
    // Consume the peeked request before closing, avoiding a TCP reset with an
    // unread request head. Never let an HTTP reader block the accept thread.
    let mut request = [0u8; HTTP_PEEK_BUF];
    let _ = stream.read(&mut request);
    stream.set_write_timeout(Some(std::time::Duration::from_millis(100)))?;
    stream.set_nonblocking(false)?;
    let mut response = format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json; charset=utf-8\r\n\
         Content-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n",
        status,
        body.len()
    );
    for (name, value) in extra_headers {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    response.push_str("\r\n");
    response.push_str(body);
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn respond_unauthorized(stream: std::net::TcpStream) -> anyhow::Result<()> {
    // No body detail, and definitely no webSocketDebuggerUrl: an unauthenticated
    // caller learns nothing about the session it cannot join.
    write_http_response(
        stream,
        "401 Unauthorized",
        &[(
            "WWW-Authenticate",
            "Bearer realm=\"obscura-shared-session\"",
        )],
        "{\"error\":\"unauthorized\"}",
    )
}

fn respond_json_status(
    stream: std::net::TcpStream,
    status: &str,
    body: serde_json::Value,
    extra_headers: &[(&str, &str)],
) -> anyhow::Result<()> {
    write_http_response(stream, status, extra_headers, &body.to_string())
}

fn dispatch_request(
    stream: std::net::TcpStream,
    state: &AcceptState,
    head: &str,
) -> anyhow::Result<()> {
    if !head.contains("\r\n\r\n") {
        return respond_json_status(
            stream,
            "431 Request Header Fields Too Large",
            json!({"error": "request head too large"}),
            &[],
        );
    }
    let Some(request) = parse_request_head(head) else {
        return respond_json_status(
            stream,
            "400 Bad Request",
            json!({"error": "bad request"}),
            &[],
        );
    };
    if request.method != "GET" {
        return respond_json_status(
            stream,
            "405 Method Not Allowed",
            json!({"error": "method not allowed"}),
            &[],
        );
    }

    let authorized = request
        .supplied_token()
        .map(|token| state.token.matches(&token))
        .unwrap_or(false);

    if request.path == "/json" || request.path.starts_with("/json/") {
        return serve_discovery(stream, state, request.path, authorized);
    }

    if !is_websocket_path(request.path) {
        // There is no unguarded second WebSocket path, and no HTTP route that
        // reaches the session.
        return respond_json_status(
            stream,
            "404 Not Found",
            json!({"error": "not found"}),
            &[],
        );
    }

    if !authorized {
        return respond_unauthorized(stream);
    }

    // A real browser page always sends Origin on a WebSocket upgrade. Refusing
    // it keeps a page the session is browsing from dialling its own debugger.
    if request.header("origin").is_some() {
        return respond_json_status(
            stream,
            "403 Forbidden",
            json!({"error": "origin not allowed"}),
            &[],
        );
    }

    let reserved = state
        .live_clients
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |live| {
            (live < state.max_clients).then_some(live + 1)
        })
        .is_ok();
    if !reserved {
        return write_http_response(
            stream,
            "503 Service Unavailable",
            &[("X-Obscura-Reason", "max-shared-clients")],
            "",
        );
    }

    let client_id = state.next_client_id.fetch_add(1, Ordering::Relaxed);
    let handoff = Handoff {
        stream,
        client_id,
        live_clients: state.live_clients.clone(),
    };
    if state.handoff_tx.try_send(handoff).is_err() {
        // The session thread is saturated. Release the slot we just reserved;
        // `handoff` is dropped with the stream and `SlotGuard` was never built.
        state.live_clients.fetch_sub(1, Ordering::AcqRel);
        return Err(anyhow::anyhow!("shared session handoff queue full"));
    }
    Ok(())
}

/// Authenticated discovery. Only reachable with a valid token, and the URLs it
/// returns carry that same token, so a client that already knows it can connect
/// without reconstructing the endpoint. Responses are `no-store` and never
/// logged.
fn serve_discovery(
    stream: std::net::TcpStream,
    state: &AcceptState,
    path: &str,
    authorized: bool,
) -> anyhow::Result<()> {
    if !authorized {
        return respond_unauthorized(stream);
    }
    let serialized_token: String = url::form_urlencoded::byte_serialize(state.token.as_str().as_bytes()).collect();
    let ip: IpAddr = state.host.parse().expect("validated loopback address");
    let base = format!("ws://{}", SocketAddr::new(ip, state.port));
    let body = match path {
        "/json/version" => json!({
            "Browser": "Chrome/145.0.0.0",
            "Protocol-Version": "1.3",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
            "V8-Version": "14.5.0.0",
            "WebKit-Version": "537.36",
            "webSocketDebuggerUrl": format!("{}/devtools/browser?token={}", base, serialized_token),
        }),
        "/json" | "/json/list" => json!([{
            "description": "",
            "devtoolsFrontendUrl": "",
            "id": "page-1",
            "title": "",
            "type": "page",
            "url": "about:blank",
            "webSocketDebuggerUrl": format!("{}/devtools/page/page-1?token={}", base, serialized_token),
        }]),
        "/json/protocol" => json!({ "version": { "major": "1", "minor": "3" } }),
        _ => {
            return respond_json_status(
                stream,
                "404 Not Found",
                json!({"error": "not found"}),
                &[],
            );
        }
    };
    write_http_response(
        stream,
        "200 OK",
        &[],
        &body.to_string(),
    )
}

/// One attached client: handshake, then a single select loop that reads commands
/// and writes responses/events. No second task, and no V8 work (all of it stays
/// with the session's processor on the same LocalSet).
async fn handle_shared_connection(handoff: Handoff, msg_tx: mpsc::Sender<ServerMessage>) {
    let _slot = SlotGuard(handoff.live_clients.clone());
    let client_id = handoff.client_id;

    let stream = match TcpStream::from_std(handoff.stream) {
        Ok(stream) => stream,
        Err(e) => {
            error!("shared session: TcpStream::from_std failed: {}", e);
            return;
        }
    };
    let mut cfg = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default();
    cfg.write_buffer_size = 0;
    cfg.max_write_buffer_size = MAX_WS_WRITE_BUFFER;
    cfg.max_message_size = Some(1024 * 1024);
    cfg.max_frame_size = Some(1024 * 1024);
    let ws_stream = match tokio_tungstenite::accept_async_with_config(stream, Some(cfg)).await {
        Ok(ws) => ws,
        Err(e) => {
            let _ = e;
            warn!("shared session: WebSocket handshake failed");
            return;
        }
    };
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    let (out_tx, mut out_rx) = mpsc::channel::<String>(SHARED_CLIENT_QUEUE);
    let (close_tx, mut close_rx) = oneshot::channel::<()>();
    let overflowed = Arc::new(AtomicBool::new(false));
    let queued_bytes = Arc::new(AtomicUsize::new(0));
    let reply = ReplyTx::shared(out_tx.clone(), overflowed.clone(), queued_bytes.clone());
    let client = SharedClient {
        id: client_id,
        tx: out_tx.clone(),
        close: Some(close_tx),
        overflowed: overflowed.clone(),
        queued_bytes: queued_bytes.clone(),
    };
    if msg_tx
        .send(ServerMessage::SharedAttach { client })
        .await
        .is_err()
    {
        return;
    }

    loop {
        tokio::select! {
            biased;
            // The processor evicts a client whose outbound queue overflowed:
            // close the socket rather than let one slow reader pin the session's
            // memory or its event fan-out.
            _ = &mut close_rx => {
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    ws_sender.send(Message::Close(None)),
                ).await;
                break;
            }
            outgoing = out_rx.recv() => match outgoing {
                Some(text) => {
                    queued_bytes.fetch_sub(text.len(), Ordering::AcqRel);
                    // `__init` is processor bookkeeping, not a client message.
                    if text == "{\"__init\":true}" {
                        continue;
                    }
                    let sent = tokio::select! {
                        _ = &mut close_rx => break,
                        sent = tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            ws_sender.send(Message::Text(text.into())),
                        ) => sent,
                    };
                    if !matches!(sent, Ok(Ok(()))) {
                        break;
                    }
                }
                None => break,
            },
            incoming = ws_receiver.next() => match incoming {
                Some(Ok(Message::Text(text))) => {
                    let text = text.to_string();
                    // `Browser.close` in shared mode detaches this client only.
                    // Killing the session would take every other client's page
                    // down with it.
                    if let Some(response) = browser_close_response(&text) {
                        let _ = tokio::time::timeout(
                            std::time::Duration::from_secs(1),
                            ws_sender.send(Message::Text(response.into())),
                        ).await;
                        break;
                    }
                    if let Some(response) = fast_path_response(&text) {
                        if reply.send(response).is_err() {
                            break;
                        }
                        continue;
                    }
                    if msg_tx
                        .send(ServerMessage::Cdp(CdpMessage {
                            text,
                            reply_tx: reply.clone(),
                        }))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Some(Ok(Message::Close(_))) => break,
                Some(Ok(_)) => {}
                Some(Err(e)) => {
                    let _ = e;
                    warn!("shared session: WS read error");
                    break;
                }
                None => break,
            },
        }
    }

    let _ = msg_tx
        .send(ServerMessage::SharedDetach { client_id })
        .await;
    info!("shared session: client {} detached", client_id);
}

/// `Browser.close` answers success and closes only the requesting client.
fn browser_close_response(text: &str) -> Option<String> {
    if !text.contains("Browser.close") {
        return None;
    }
    let req: CdpRequest = serde_json::from_str(text).ok()?;
    if req.method != "Browser.close" {
        return None;
    }
    serde_json::to_string(&crate::types::CdpResponse::success(
        req.id,
        json!({}),
        req.session_id,
    ))
    .ok()
}

#[cfg(test)]
mod tests {
    use super::{
        browser_close_response, constant_time_eq, is_websocket_path, parse_request_head,
        SessionToken, SharedSessionConfig, MIN_SESSION_TOKEN_LEN,
    };

    fn secret() -> String {
        "0123456789abcdefghijklmnopqrstuvwxyz".to_string()
    }

    #[test]
    fn token_debug_is_redacted_and_comparison_is_exact() {
        let token = SessionToken::new(&secret()).expect("token");
        let debug = format!("{:?}", token);
        assert_eq!(debug, "SessionToken(<redacted>)");
        assert!(!debug.contains(&secret()));
        assert!(token.matches(&secret()));
        assert!(!token.matches(&secret().to_uppercase()));
        assert!(!token.matches(""));
    }

    #[test]
    fn token_validation_rejects_short_weak_and_unsafe_secrets() {
        assert!(SessionToken::new(&"a".repeat(MIN_SESSION_TOKEN_LEN - 1)).is_err());
        assert!(SessionToken::new(&"a".repeat(MIN_SESSION_TOKEN_LEN)).is_ok());
        // Characters that would need escaping in the CDP URL's query string.
        assert!(SessionToken::new(&format!("{}&x=1", "a".repeat(MIN_SESSION_TOKEN_LEN))).is_err());
        assert!(SessionToken::new(&format!("{} ", "a".repeat(MIN_SESSION_TOKEN_LEN))).is_err());
        assert!(SessionToken::new(&format!("{}\n", "a".repeat(MIN_SESSION_TOKEN_LEN))).is_err());
    }

    #[test]
    fn constant_time_eq_only_matches_equal_bytes() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn shared_config_refuses_non_loopback_hosts() {
        let token = SessionToken::new(&secret()).expect("token");
        assert!(SharedSessionConfig::new(0, "127.0.0.1", token.clone()).is_ok());
        assert!(SharedSessionConfig::new(0, "::1", token.clone()).is_ok());
        for host in ["0.0.0.0", "192.168.1.10", "::", "example.com"] {
            let error = SharedSessionConfig::new(0, host, token.clone())
                .expect_err("non-loopback host must be refused");
            assert!(error.to_string().contains("loopback"), "{error}");
        }
    }

    #[test]
    fn request_head_parses_path_query_and_bearer() {
        let head = "GET /devtools/browser?token=abc HTTP/1.1\r\nHost: 127.0.0.1:9222\r\nAuthorization: Bearer xyz\r\n\r\n";
        let request = parse_request_head(head).expect("parsed");
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/devtools/browser");
        assert_eq!(request.query, Some("token=abc"));
        assert_eq!(request.supplied_token().as_deref(), Some("xyz"));

        let query_only = "GET /devtools/browser?token=abc%2Ddef HTTP/1.1\r\n\r\n";
        let request = parse_request_head(query_only).expect("parsed");
        assert_eq!(request.supplied_token().as_deref(), Some("abc-def"));
    }

    #[test]
    fn absolute_form_targets_are_refused() {
        assert!(parse_request_head("GET http://127.0.0.1:9222/json HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn only_devtools_paths_are_websockets() {
        assert!(is_websocket_path("/devtools/browser"));
        assert!(is_websocket_path("/devtools/page/page-1"));
        for path in ["/ws", "/json/version", "/devtools", "/devtools/"] {
            assert!(!is_websocket_path(path), "{path} must not be a websocket path");
        }
    }

    #[test]
    fn browser_close_is_detected_by_method_not_substring() {
        assert!(browser_close_response(r#"{"id":1,"method":"Browser.close"}"#).is_some());
        assert!(browser_close_response(
            r#"{"id":2,"method":"Runtime.evaluate","params":{"expression":"'Browser.close'"}}"#
        )
        .is_none());
    }
}
