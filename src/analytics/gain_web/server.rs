//! HTTP server loop for `gain --web`.
//!
//! `tiny_http` chosen for footprint: pure-Rust, no async runtime, ~300KB.
//! We deliberately avoid `hyper` + `tokio` — RTK's whole budget is single-
//! threaded blocking I/O (see `rust-patterns.md`).

use anyhow::{Context, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tiny_http::{Header, Method, Response, Server};

use super::api;

/// Server stops accepting connections after this much zero-request idle.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// How often we wake from `recv_timeout` to check the idle clock.
const POLL_INTERVAL: Duration = Duration::from_secs(60);

pub fn run(port: Option<u16>, no_browser: bool) -> Result<()> {
    let bind = format!("127.0.0.1:{}", port.unwrap_or(0));
    let server = Server::http(&bind)
        .map_err(|e| anyhow::anyhow!("Failed to bind dashboard server: {e}"))?;

    let bound_port = match server.server_addr() {
        tiny_http::ListenAddr::IP(addr) => addr.port(),
        tiny_http::ListenAddr::Unix(_) => {
            anyhow::bail!("dashboard server bound to a unix socket — expected TCP")
        }
    };
    let url = format!("http://127.0.0.1:{bound_port}/");

    eprintln!("contextcrawler dashboard: {url}");
    eprintln!("  (read-only, loopback-only, auto-shutdown after 1h idle — Ctrl+C to exit)");

    if !no_browser {
        if let Err(e) = open_browser(&url) {
            eprintln!("contextcrawler: could not auto-open browser ({e}); open {url} manually");
        }
    }

    // Ctrl+C handler — best-effort. tiny_http doesn't expose a graceful stop
    // hook, so on SIGINT we just exit fast.
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_signal = Arc::clone(&shutdown);
    ctrlc_handler(shutdown_signal);

    let mut last_request = Instant::now();
    loop {
        if shutdown.load(Ordering::Relaxed) {
            eprintln!("contextcrawler: shutdown requested, exiting.");
            return Ok(());
        }
        match server
            .recv_timeout(POLL_INTERVAL)
            .context("dashboard server recv error")?
        {
            Some(request) => {
                last_request = Instant::now();
                handle(request);
            }
            None => {
                if last_request.elapsed() >= IDLE_TIMEOUT {
                    eprintln!("contextcrawler: dashboard idle for 1h, shutting down.");
                    return Ok(());
                }
            }
        }
    }
}

fn handle(request: tiny_http::Request) {
    if !matches!(request.method(), Method::Get | Method::Head) {
        let _ = request.respond(text_response(405, "method not allowed"));
        return;
    }

    // tiny_http exposes the path as the full request-target (may include
    // query string). Trim the query for routing.
    let path = request.url().split('?').next().unwrap_or("/").to_string();

    let response_result = match path.as_str() {
        "/" | "/index.html" => Ok(index_response()),
        "/api/summary" => api::summary().map(json_response),
        "/api/by-day" => api::by_day().map(json_response),
        "/api/weak-filters" => api::weak_filters().map(json_response),
        "/api/failures" => api::failures().map(json_response),
        "/api/boundaries" => api::boundaries().map(json_response),
        "/api/insights" => api::insights().map(json_response),
        _ => Ok(text_response(404, "not found")),
    };

    match response_result {
        Ok(resp) => {
            let _ = request.respond(resp);
        }
        Err(e) => {
            eprintln!("contextcrawler dashboard: API error on {path}: {e:#}");
            let body = format!("{{\"error\":{}}}", json_str_lit(&e.to_string()));
            let _ = request.respond(json_response_with_status(500, body));
        }
    }
}

fn index_response() -> Response<std::io::Cursor<Vec<u8>>> {
    // Slice 1 stub. The full neon SPA lands in slice 3.
    let body = include_str!("assets/index.html");
    Response::from_string(body)
        .with_header(html_header())
        .with_status_code(200)
}

fn json_response(body: String) -> Response<std::io::Cursor<Vec<u8>>> {
    json_response_with_status(200, body)
}

fn json_response_with_status(status: u16, body: String) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(body)
        .with_header(json_header())
        .with_status_code(status)
}

fn text_response(status: u16, body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(body.to_string()).with_status_code(status)
}

fn html_header() -> Header {
    Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..])
        .expect("static header literal is valid")
}

fn json_header() -> Header {
    Header::from_bytes(&b"Content-Type"[..], &b"application/json; charset=utf-8"[..])
        .expect("static header literal is valid")
}

/// Minimal JSON string literal escaper for our error fallback path.
/// `serde_json::to_string` is the right tool everywhere else.
fn json_str_lit(s: &str) -> String {
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

fn open_browser(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    let (cmd, args): (&str, Vec<&str>) = ("open", vec![url]);
    #[cfg(target_os = "linux")]
    let (cmd, args): (&str, Vec<&str>) = ("xdg-open", vec![url]);
    #[cfg(target_os = "windows")]
    let (cmd, args): (&str, Vec<&str>) = ("cmd", vec!["/C", "start", "", url]);

    std::process::Command::new(cmd)
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|_| ())
}

#[cfg(unix)]
fn ctrlc_handler(flag: Arc<AtomicBool>) {
    // Lightweight SIGINT handler via libc::signal. We don't pull the
    // `ctrlc` crate just for this — tiny_http's recv_timeout means we'll
    // notice the flag within POLL_INTERVAL.
    use std::sync::Mutex;
    static HANDLER: Mutex<Option<Arc<AtomicBool>>> = Mutex::new(None);
    *HANDLER.lock().unwrap() = Some(flag);
    extern "C" fn on_sigint(_: libc::c_int) {
        if let Some(f) = HANDLER.lock().unwrap().as_ref() {
            f.store(true, Ordering::Relaxed);
        }
    }
    unsafe {
        libc::signal(libc::SIGINT, on_sigint as *const () as libc::sighandler_t);
    }
}

#[cfg(not(unix))]
fn ctrlc_handler(_flag: Arc<AtomicBool>) {
    // On non-unix we rely on default ^C behaviour terminating the process.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_str_lit_escapes_quotes_backslash_newline_control() {
        assert_eq!(json_str_lit("hi"), "\"hi\"");
        assert_eq!(json_str_lit("a\"b"), "\"a\\\"b\"");
        assert_eq!(json_str_lit("a\\b"), "\"a\\\\b\"");
        assert_eq!(json_str_lit("a\nb"), "\"a\\nb\"");
        assert_eq!(json_str_lit("a\x01b"), "\"a\\u0001b\"");
    }
}
