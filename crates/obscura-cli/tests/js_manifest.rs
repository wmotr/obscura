use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

fn fixture() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                    continue;
                }
                Err(error) => panic!("fixture accept: {error}"),
            };
            stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut request = [0; 4096];
            let count = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..count]);
            let (kind, body) = if request.starts_with("GET /manifest") {
                ("application/json", r#"{"matcher":{"static":{},"wildcard":{},"dynamic":{}}}"#)
            } else {
                ("text/html", r#"<!doctype html><title>pending</title><script>
                (async () => {
                    // Match ofetch's body guard used by Nuxt manifest loading.
                    async function manifest() {
                        const response = await fetch('/manifest');
                        return response.body ? await response.json() : undefined;
                    }
                    const values = await Promise.all(Array.from({length: 64}, async () => {
                        const value = await manifest();
                        for (let i = 0; i < 200; i++) {
                            document.body.setAttribute('data-tick', String(i));
                        }
                        return !!value?.matcher;
                    }));
                    document.title = values.every(Boolean) ? 'manifest-ready' : 'manifest-missing';
                })().catch(error => { document.title = 'error:' + error; });
                </script>"#)
            };
            let response = format!("HTTP/1.1 200 OK\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            let _ = stream.write_all(response.as_bytes());
        }
    });
    url
}

#[test]
fn concurrent_manifest_fetches_decode_without_reentrant_ops() {
    check_manifest(None);
}

#[test]
fn manifest_fetches_export_spans_on_shutdown_in_quiet_mode() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}/v1/traces", listener.local_addr().unwrap());
    let (sender, receiver) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok((mut stream, _)) = listener.accept() {
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut request = Vec::new();
                let mut buffer = [0; 8192];
                while let Ok(count) = stream.read(&mut buffer) {
                    if count == 0 { break; }
                    request.extend_from_slice(&buffer[..count]);
                    if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&request[..end]);
                        let length = headers.lines().find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().ok()).flatten()
                        }).unwrap_or(0);
                        if request.len() >= end + 4 + length { break; }
                    }
                }
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                let _ = sender.send(request);
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
    });
    check_manifest(Some(&endpoint));
    let request = receiver.recv_timeout(Duration::from_secs(5)).expect("OTLP export before exit");
    let text = String::from_utf8_lossy(&request);
    assert!(text.starts_with("POST /v1/traces "), "{text}");
    assert!(text.contains("browser.navigate"), "missing navigation span: {text}");
}

#[test]
fn worker_decodes_concurrent_manifest_fetches() {
    let url = fixture();
    let mut child = Command::new(env!("CARGO_BIN_EXE_obscura-worker"))
        .env("OBSCURA_ALLOW_PRIVATE_NETWORK", "1")
        .env_remove("OBSCURA_PROXY")
        .env_remove("OBSCURA_STEALTH")
        .env_remove("OBSCURA_OBEY_ROBOTS")
        .env_remove("OTEL_EXPORTER_OTLP_ENDPOINT")
        .env_remove("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    for command in [
        serde_json::json!({"cmd": "navigate", "url": url}),
        serde_json::json!({"cmd": "evaluate", "expression": "(async () => { for (let i = 0; i < 100 && document.title === 'pending'; i++) await new Promise(resolve => setTimeout(resolve, 25)); return document.title; })()"}),
        serde_json::json!({"cmd": "shutdown"}),
    ] {
        writeln!(stdin, "{command}").unwrap();
    }
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let responses: Vec<serde_json::Value> = stdout.lines()
        .map(|line| serde_json::from_str(line).expect("worker JSON response"))
        .collect();
    assert_eq!(responses.len(), 3, "{stdout}");
    assert_eq!(responses[1]["result"], "manifest-ready", "{stdout}");
}

fn check_manifest(endpoint: Option<&str>) {
    let url = fixture();
    let mut command = Command::new(env!("CARGO_BIN_EXE_obscura"));
    command
        .args(["--allow-private-network", "fetch", &url, "--wait", "3", "--eval", "document.title", "--quiet"])
        .env_remove("OTEL_EXPORTER_OTLP_ENDPOINT")
        .env_remove("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
        .env("OTEL_SERVICE_NAME", "obscura-test")
        .env("OTEL_RESOURCE_ATTRIBUTES", "")
        .env("OTEL_EXPORTER_OTLP_HEADERS", "")
        .env("OTEL_EXPORTER_OTLP_TRACES_HEADERS", "");
    if let Some(endpoint) = endpoint {
        command.env("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", endpoint);
    }
    let output = command.output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8_lossy(&output.stdout).contains("manifest-ready"), "stdout: {} stderr: {}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
}
