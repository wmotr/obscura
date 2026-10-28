//! `obscura serve --shared-session` lets several authorized CDP clients attach
//! to one page while the default mode keeps a session per connection.
//!
//! The properties pinned here are the ones that would silently regress:
//!
//! 1. two clients, and a client that reconnects, see the same DOM and cookies;
//! 2. a default (non shared) server still isolates connections from each other;
//! 3. two clients may reuse command ids and each receives only its own reply;
//! 4. the token protects the WebSocket endpoint and the discovery documents,
//!    including alternate WebSocket paths, and an `Origin` header is refused;
//! 5. the token file is validated (permissions, length) and non loopback hosts
//!    are rejected;
//! 6. two shared sessions in two processes never see each other's pages.
//!
//! Run with `cargo nextest run -p obscura-cdp --features render -E 'test(shared_session)'`.

#![cfg(unix)]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

use obscura_cdp::shared_session::{start_shared_session, SessionToken, SharedSessionConfig};
use obscura_cdp::start_with_serve_options_and_limit;

const TOKEN: &str = "0123456789abcdef0123456789abcdef-shared-session-test";
const PAGE_PATH: &str = "/devtools/browser";

static TEMP_SEQUENCE: AtomicU32 = AtomicU32::new(0);

async fn pick_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Writes a token file with the given contents and mode and returns its path.
fn token_file(contents: &str, mode: u32) -> PathBuf {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "obscura-shared-session-{}-{}.token",
        std::process::id(),
        sequence
    ));
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(contents.as_bytes()).unwrap();
    file.flush().unwrap();
    drop(file);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

fn valid_token_file() -> PathBuf {
    token_file(TOKEN, 0o600)
}

struct SharedServer {
    port: u16,
    token_path: PathBuf,
}

/// Starts a shared session in the background and waits until it accepts TCP.
async fn start_shared(max_clients: usize) -> SharedServer {
    let port = pick_port().await;
    let token_path = valid_token_file();
    let config = SharedSessionConfig::from_token_file(
        port,
        "127.0.0.1",
        &token_path,
        None,
        false,
        None,
        false,
        true,
        max_clients,
    )
    .unwrap();
    tokio::spawn(async move {
        let _ = start_shared_session(config).await;
    });
    wait_for_listener(port).await;
    SharedServer { port, token_path }
}

async fn wait_for_listener(port: u16) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "shared session did not start listening on {port}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

type Client = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// A page-level CDP client that drains events and matches replies by id.
struct Page {
    ws: Client,
    id: u64,
    session: Option<String>,
}

impl Page {
    async fn connect(port: u16, path: &str, query: &str) -> Result<Self, String> {
        let url = format!("ws://127.0.0.1:{port}{path}{query}");
        let (ws, _) = connect_async(&url).await.map_err(|e| e.to_string())?;
        Ok(Self::from_socket(ws).await)
    }

    async fn from_socket(ws: Client) -> Self {
        let mut page = Self { ws, id: 1, session: None };
        let targets = page.command("Target.getTargets", json!({})).await;
        let target = if let Some(target) = targets["result"]["targetInfos"].as_array()
            .and_then(|targets| targets.iter().find(|target| target["type"] == "page")) {
            target["targetId"].clone()
        } else {
            page.command("Target.createTarget", json!({"url": "about:blank"})).await["result"]["targetId"].clone()
        };
        let attached = page.command("Target.attachToTarget", json!({"targetId": target, "flatten": true})).await;
        page.session = Some(attached["result"]["sessionId"].as_str().expect("flattened session").to_string());
        page
    }

    async fn connect_authorized(port: u16) -> Self {
        Self::connect(port, PAGE_PATH, &format!("?token={TOKEN}"))
            .await
            .expect("authorized page connection")
    }

    async fn send(&mut self, id: u64, method: &str, params: Value) -> Result<Value, String> {
        let session = if method.starts_with("Target.") || method.starts_with("Browser.") {
            None
        } else { self.session.clone() };
        self.send_in_session(id, method, params, session.as_deref()).await
    }

    async fn send_in_session(&mut self, id: u64, method: &str, params: Value, session: Option<&str>) -> Result<Value, String> {
        let mut payload = json!({"id": id, "method": method, "params": params});
        if let Some(session) = session {
            payload["sessionId"] = json!(session);
        }
        self.ws
            .send(Message::Text(payload.to_string().into()))
            .await
            .map_err(|e| e.to_string())?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(format!("timeout waiting for reply to {method}"));
            }
            let next = tokio::time::timeout(Duration::from_secs(10), self.ws.next())
                .await
                .map_err(|_| format!("timeout reading reply to {method}"))?
                .ok_or_else(|| "websocket closed".to_string())?;
            let text = match next.map_err(|e| e.to_string())? {
                Message::Text(text) => text.to_string(),
                _ => continue,
            };
            let value: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
            if value.get("id").and_then(Value::as_u64) == Some(id) {
                return Ok(value);
            }
        }
    }

    async fn command(&mut self, method: &str, params: Value) -> Value {
        let id = self.id;
        self.id += 1;
        self.send(id, method, params).await.expect(method)
    }

    async fn navigate_to_marker(&mut self, marker: &str) {
        self.command(
            "Page.navigate",
            json!({"url": format!("data:text/html,<title>{marker}</title><body>{marker}</body>")}),
        )
        .await;
    }

    /// Evaluates an expression and returns its string value.
    async fn eval(&mut self, expression: &str) -> String {
        let reply = self
            .command(
                "Runtime.evaluate",
                json!({"expression": expression, "returnByValue": true}),
            )
            .await;
        let value = reply
            .pointer("/result/result/value")
            .or_else(|| reply.pointer("/result/value"))
            .cloned()
            .unwrap_or(Value::Null);
        match value {
            Value::String(text) => text,
            other => other.to_string(),
        }
    }
}

async fn http_get(port: u16, path: &str) -> (String, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut raw))
        .await.expect("HTTP response timeout").unwrap();
    let text = String::from_utf8_lossy(&raw).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    (head.to_string(), body.to_string())
}

#[tokio::test]
async fn page_and_cookies_are_shared_across_clients_and_reconnect() {
    let server = start_shared(4).await;

    let mut first = Page::connect_authorized(server.port).await;
    first.navigate_to_marker("shared-title").await;
    let written = first
        .eval("document.title")
        .await;
    assert!(written.contains("shared-title"), "first client saw {written}");
    assert_eq!(first.eval("'__init'").await, "__init",
        "bookkeeping must not swallow a legitimate evaluation result");

    let set = first.command("Network.setCookie", json!({"name": "k", "value": "v", "url": "https://shared.example/"})).await;
    assert_eq!(set["result"]["success"], true);
    let mut second = Page::connect_authorized(server.port).await;
    assert_eq!(second.eval("document.title").await, "shared-title");
    let cookies = second.command("Network.getCookies", json!({})).await;
    assert!(cookies["result"]["cookies"].as_array().unwrap().iter()
        .any(|cookie| cookie["name"] == "k" && cookie["value"] == "v"));

    // The page belongs to the process, so dropping one client leaves it intact
    // for a client that connects afterwards.
    drop(first);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut third = Page::connect_authorized(server.port).await;
    assert_eq!(third.eval("document.title").await, "shared-title");
    let cookies = third.command("Network.getCookies", json!({})).await;
    assert!(cookies["result"]["cookies"].as_array().unwrap().iter()
        .any(|cookie| cookie["name"] == "k" && cookie["value"] == "v"));
}

#[tokio::test]
async fn default_server_keeps_connections_isolated() {
    let port = pick_port().await;
    tokio::spawn(async move {
        let _ = start_with_serve_options_and_limit(
            port, "127.0.0.1", None, false, None, false, None, true, 4,
        )
        .await;
    });
    wait_for_listener(port).await;

    let mut first: Page = Page::connect(port, PAGE_PATH, "")
        .await
        .unwrap_or_else(|e| panic!("default page connection: {e}"));
    first.navigate_to_marker("isolated-title").await;
    let written = first
        .eval("document.title")
        .await;
    assert!(written.contains("isolated-title"), "first client saw {written}");

    first.command("Network.setCookie", json!({"name": "k", "value": "v", "url": "https://isolated.example/"})).await;
    let mut second: Page = Page::connect(port, PAGE_PATH, "")
        .await
        .unwrap_or_else(|e| panic!("second default page connection: {e}"));
    let read = second
        .eval("(function(){ return document.title + '|' + document.cookie; })()")
        .await;
    assert!(
        !read.contains("isolated-title") && !read.contains("k=v"),
        "default mode must isolate connections, second client saw {read}"
    );
    let cookies = second.command("Network.getCookies", json!({})).await;
    assert!(!cookies["result"]["cookies"].as_array().unwrap().iter().any(|cookie| cookie["name"] == "k"));
}

#[tokio::test]
async fn identical_command_ids_are_answered_to_their_requester() {
    let server = start_shared(4).await;
    let mut first = Page::connect_authorized(server.port).await;
    let mut second = Page::connect_authorized(server.port).await;
    first.navigate_to_marker("routing").await;

    // The same id on both connections, with different expressions.
    let (first_reply, second_reply) = tokio::join!(
        first.send(
            7, "Runtime.evaluate",
            json!({"expression": "'client-a'", "returnByValue": true}),
        ),
        second.send(
            7, "Runtime.evaluate",
            json!({"expression": "'client-b'", "returnByValue": true}),
        ),
    );
    let first_reply = first_reply.expect("first reply");
    let second_reply = second_reply.expect("second reply");

    assert_eq!(
        first_reply.pointer("/result/result/value"),
        Some(&Value::String("client-a".into())),
        "first client must get its own result: {first_reply}"
    );
    assert_eq!(
        second_reply.pointer("/result/result/value"),
        Some(&Value::String("client-b".into())),
        "second client must get its own result: {second_reply}"
    );
}

#[tokio::test]
async fn token_protects_websocket_and_discovery() {
    let server = start_shared(4).await;

    let missing = Page::connect(server.port, PAGE_PATH, "").await;
    assert!(missing.is_err(), "connection without a token must fail");

    let wrong = Page::connect(server.port, PAGE_PATH, "?token=not-the-token").await;
    assert!(wrong.is_err(), "connection with a wrong token must fail");

    let alternate_path = Page::connect(server.port, "/devtools/page/page-1", "").await;
    assert!(
        alternate_path.is_err(),
        "browser endpoint without a token must fail"
    );

    let (head, body) = http_get(server.port, "/json/version").await;
    assert!(head.contains("401"), "unauthenticated discovery head: {head}");
    assert!(
        !body.contains("webSocketDebuggerUrl"),
        "unauthenticated discovery must not leak an authenticated endpoint: {body}"
    );

    let (head, body) = http_get(server.port, &format!("/json/version?token={TOKEN}")).await;
    assert!(head.contains("200"), "authenticated discovery head: {head}");
    assert!(
        body.contains("/devtools/browser") && body.contains(TOKEN),
        "authenticated discovery must expose the endpoint: {body}"
    );
    let _ = std::fs::remove_file(server.token_path);
}

#[tokio::test]
async fn origin_header_on_the_upgrade_is_refused() {
    let server = start_shared(2).await;
    let mut stream = TcpStream::connect(("127.0.0.1", server.port))
        .await
        .unwrap();
    let request = format!(
        "GET {PAGE_PATH}?token={TOKEN} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nOrigin: https://evil.example\r\n\r\n",
        server.port
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut raw)).await;
    let head = String::from_utf8_lossy(&raw).to_string();
    assert!(
        head.contains("403"),
        "an Origin header must be refused, got: {head}"
    );
}

#[test]
fn token_file_is_validated_and_hosts_are_loopback_only() {
    let too_short = token_file("short-token", 0o600);
    assert!(
        SessionToken::from_file(&too_short).is_err(),
        "a short token must be rejected"
    );

    let empty = token_file("", 0o600);
    assert!(
        SessionToken::from_file(&empty).is_err(),
        "an empty token must be rejected"
    );

    let group_readable = token_file(TOKEN, 0o644);
    assert!(
        SessionToken::from_file(&group_readable).is_err(),
        "a token file readable by others must be rejected"
    );

    let valid = valid_token_file();
    assert!(
        SessionToken::from_file(&valid).is_ok(),
        "a 0600 token file with enough entropy must be accepted"
    );

    let wildcard = SharedSessionConfig::from_token_file(
        9222,
        "0.0.0.0",
        &valid,
        None,
        false,
        None,
        false,
        false,
        4,
    );
    assert!(
        wildcard.is_err(),
        "a wildcard bind host must be rejected in shared mode"
    );

    let newline = token_file(&format!("{TOKEN}\n"), 0o600);
    assert!(SessionToken::from_file(&newline).is_ok());
    let space = token_file(&format!("{TOKEN} "), 0o600);
    assert!(SessionToken::from_file(&space).is_err());
    #[cfg(target_env = "gnu")]
    {
        let link = valid.with_extension("link");
        std::os::unix::fs::symlink(&valid, &link).unwrap();
        assert!(SessionToken::from_file(&link).is_err());
        std::fs::remove_file(link).unwrap();
        let fifo = valid.with_extension("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(SessionToken::from_file(&fifo).is_err());
        std::fs::remove_file(fifo).unwrap();
    }
    for path in [too_short, empty, group_readable, valid, newline, space] {
        let _ = std::fs::remove_file(path);
    }
}

#[tokio::test]
async fn two_shared_sessions_never_share_a_page() {
    let first_server = start_shared(2).await;
    let second_server = start_shared(2).await;

    let mut first = Page::connect_authorized(first_server.port).await;
    first.navigate_to_marker("process-one").await;
    let written = first.eval("document.title").await;
    assert!(written.contains("process-one"), "first process saw {written}");

    let mut second = Page::connect_authorized(second_server.port).await;
    let read = second.eval("document.title").await;
    assert!(
        !read.contains("process-one"),
        "a second process must not see the first process' page, got {read}"
    );
}

#[tokio::test]
async fn bearer_auth_and_browser_close_preserve_shared_state() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let server = start_shared(1).await;
    let mut request = format!("ws://127.0.0.1:{}/devtools/browser", server.port)
        .into_client_request().unwrap();
    request.headers_mut().insert("Authorization", format!("Bearer {TOKEN}").parse().unwrap());
    let (ws, _) = connect_async(request).await.expect("bearer authentication");
    let mut first = Page::from_socket(ws).await;
    first.navigate_to_marker("still-alive").await;
    let refused = Page::connect(server.port, PAGE_PATH, &format!("?token={TOKEN}"))
        .await.err().expect("client cap");
    assert!(refused.contains("503"), "{refused}");
    let reply = first.command("Browser.close", json!({})).await;
    assert!(reply.get("result").is_some(), "{reply}");
    drop(first);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut second = Page::connect_authorized(server.port).await;
    assert_eq!(second.eval("document.title").await, "still-alive");
}

#[tokio::test]
async fn oversized_upgrade_cannot_hide_an_origin_header() {
    let server = start_shared(1).await;
    let mut stream = TcpStream::connect(("127.0.0.1", server.port)).await.unwrap();
    let request = format!(
        "GET {PAGE_PATH}?token={TOKEN} HTTP/1.1\r\nHost: localhost\r\nX-Padding: {}\r\nOrigin: https://evil.example\r\n\r\n",
        "x".repeat(5000),
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut raw)).await;
    assert!(String::from_utf8_lossy(&raw).contains("431"));
}

#[tokio::test]
async fn separate_flattened_clients_fill_the_same_form() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut head = [0u8; 4096];
            let _ = socket.read(&mut head).await;
            let body = "<html><body><form><input id='password' type='password'></form></body></html>";
            let response = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
            let _ = socket.write_all(response.as_bytes()).await;
        }
    });
    let server = start_shared(4).await;
    let mut harness = Page::connect(server.port, "/devtools/browser", &format!("?token={TOKEN}")).await.unwrap();
    let targets = harness.command("Target.getTargets", json!({})).await;
    let target = targets["result"]["targetInfos"][0]["targetId"].as_str().unwrap();
    let attached = harness.command("Target.attachToTarget", json!({"targetId": target, "flatten": true})).await;
    let harness_session = attached["result"]["sessionId"].as_str().unwrap();
    let navigation = harness.send_in_session(30, "Page.navigate", json!({"url": format!("{origin}/login")}), Some(harness_session)).await.unwrap();
    assert!(navigation.get("error").is_none(), "{navigation}");

    let mut supervisor = Page::connect(server.port, "/devtools/browser", &format!("?token={TOKEN}")).await.unwrap();
    let attached = supervisor.command("Target.attachToTarget", json!({"targetId": target, "flatten": true})).await;
    let supervisor_session = attached["result"]["sessionId"].as_str().unwrap();
    assert_ne!(harness_session, supervisor_session);
    let expression = format!(
        "(() => {{ if (location.origin !== {}) return {{refused: 'origin_changed'}}; const field = document.getElementById('password'); field.value = 'fake-vault-canary'; field.dispatchEvent(new Event('input', {{bubbles:true}})); return {{filled: 1}}; }})()",
        serde_json::to_string(&origin).unwrap(),
    );
    let fill = supervisor.send_in_session(31, "Runtime.evaluate", json!({"expression": expression, "returnByValue": true}), Some(supervisor_session)).await.unwrap();
    assert_eq!(fill.pointer("/result/result/value/filled"), Some(&json!(1)), "{fill}");
    assert!(!fill.to_string().contains("fake-vault-canary"));
    let read = harness.send_in_session(32, "Runtime.evaluate", json!({"expression": "document.getElementById('password').value", "returnByValue": true}), Some(harness_session)).await.unwrap();
    assert_eq!(read.pointer("/result/result/value"), Some(&json!("fake-vault-canary")), "{read}");
    let refusal = supervisor.send_in_session(33, "Runtime.evaluate", json!({"expression": "(() => { if (location.origin !== 'https://wrong.example') return {refused: 'origin_changed'}; document.getElementById('password').value = 'wrong'; return {filled: 1}; })()", "returnByValue": true}), Some(supervisor_session)).await.unwrap();
    assert_eq!(refusal.pointer("/result/result/value/refused"), Some(&json!("origin_changed")));
}

#[tokio::test]
async fn secret_expressions_and_malformed_frames_are_not_logged() {
    use std::sync::{Arc, Mutex};
    use std::sync::atomic::{AtomicU64, Ordering};
    use tracing::{Event, Metadata, Subscriber, field::{Field, Visit}, span::{Attributes, Id, Record}};

    struct Fields<'a>(&'a mut String);
    impl Visit for Fields<'_> {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0.push_str(&format!("{field}={value:?}\n"));
        }
    }
    struct Capture { logs: Arc<Mutex<String>>, next: AtomicU64 }
    impl Subscriber for Capture {
        fn enabled(&self, _: &Metadata<'_>) -> bool { true }
        fn new_span(&self, attrs: &Attributes<'_>) -> Id {
            attrs.record(&mut Fields(&mut self.logs.lock().unwrap()));
            Id::from_u64(self.next.fetch_add(1, Ordering::Relaxed))
        }
        fn record(&self, _: &Id, values: &Record<'_>) {
            values.record(&mut Fields(&mut self.logs.lock().unwrap()));
        }
        fn record_follows_from(&self, _: &Id, _: &Id) {}
        fn event(&self, event: &Event<'_>) {
            event.record(&mut Fields(&mut self.logs.lock().unwrap()));
        }
        fn enter(&self, _: &Id) {}
        fn exit(&self, _: &Id) {}
    }
    let logs = Arc::new(Mutex::new(String::new()));
    tracing::subscriber::set_global_default(Capture { logs: logs.clone(), next: AtomicU64::new(1) }).unwrap();
    let server = start_shared(2).await;
    let mut page = Page::connect_authorized(server.port).await;
    page.navigate_to_marker("logging-check").await;
    assert_eq!(page.eval("(() => { document.body.innerHTML = '<input id=password type=password>'; const field = document.getElementById('password'); field.value = 'fake-vault-log-canary'; field.dispatchEvent(new Event('input', {bubbles:true})); return true; })()").await, "true");
    page.ws.send(Message::Text("{\"id\":\"fake-vault-log-canary\",\"method\":\"Runtime.evaluate\"}".into())).await.unwrap();
    assert_eq!(page.eval("true").await, "true");
    let captured = logs.lock().unwrap();
    assert!(captured.contains("Invalid CDP JSON"), "the malformed frame must exercise the warning path");
    assert!(!captured.contains("fake-vault-log-canary"), "a credential expression or malformed frame reached the logs");
    assert!(!captured.contains(TOKEN), "the endpoint token reached the logs");
}

#[tokio::test]
async fn healthy_reader_survives_a_burst_larger_than_its_queue() {
    let server = start_shared(2).await;
    let mut page = Page::connect_authorized(server.port).await;
    page.navigate_to_marker("event-burst").await;
    page.command("Runtime.enable", json!({})).await;
    assert_eq!(page.eval("(() => { for (let i = 0; i < 600; i++) console.log(i); return 'burst-ok'; })()").await, "burst-ok");
    assert_eq!(page.eval("document.title").await, "event-burst");
}

#[tokio::test]
async fn target_events_are_broadcast_to_other_authorized_clients() {
    let server = start_shared(2).await;
    let mut first = Page::connect_authorized(server.port).await;
    let mut second = Page::connect_authorized(server.port).await;
    let created = first.command("Target.createTarget", json!({"url": "about:blank"})).await;
    let target = &created["result"]["targetId"];
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let frame = second.ws.next().await.expect("event stream").unwrap();
            if let Message::Text(text) = frame {
                let event: Value = serde_json::from_str(&text).unwrap();
                if event["method"] == "Target.targetCreated" && event["params"]["targetInfo"]["targetId"] == *target {
                    break;
                }
            }
        }
    }).await.expect("other client must receive target events");
}

