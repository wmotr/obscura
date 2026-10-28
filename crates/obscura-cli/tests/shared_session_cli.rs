#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::process::Command;

const TOKEN: &str = "fake-session-token-never-log-this-value-1234567890";

fn refusal(args: &[&str], expected: &str) {
    let output = Command::new(env!("CARGO_BIN_EXE_obscura"))
        .env_remove("OTEL_EXPORTER_OTLP_ENDPOINT")
        .env_remove("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
        .args(args).output().expect("CLI starts");
    assert!(!output.status.success(), "invalid shared mode must fail");
    let text = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(text.contains(expected), "expected {expected:?}, got {text}");
    assert!(!text.contains(TOKEN), "the session token must not be logged");
}

#[test]
fn shared_session_requires_explicit_authentication() {
    refusal(&["serve", "--shared-session"], "requires --session-token-file");
    refusal(&["serve", "--session-token-file", "/nonexistent/token"], "--shared-session");
}

#[test]
fn shared_session_rejects_workers_and_persistence() {
    refusal(&["serve", "--shared-session", "--session-token-file", "/nonexistent/token", "--workers", "2"], "single process");
    refusal(&["serve", "--shared-session", "--session-token-file", "/nonexistent/token", "--storage-dir", "/nonexistent/storage"], "refuses --storage-dir");
}

#[test]
fn shared_session_refuses_exposed_token_files_without_logging_their_contents() {
    let path = std::env::temp_dir().join(format!("obscura-cli-shared-{}.token", std::process::id()));
    std::fs::write(&path, TOKEN).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    refusal(&["serve", "--shared-session", "--session-token-file", path.to_str().unwrap()], "group/other access is refused");
    std::fs::remove_file(path).unwrap();
}
