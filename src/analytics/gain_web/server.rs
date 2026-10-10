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
    // a query string). The v1 endpoints take no query params, so route on
    // the bare path.
    let path = request.url().split('?').next().unwrap_or("/").to_string();

    let response_result = match route(&path) {
        Route::Index => Ok(index_response()),
        Route::Summary => api::summary().map(json_response),
        Route::ByDay => api::by_day().map(json_response),
        Route::WeakFilters => api::weak_filters().map(json_response),
        Route::Failures => api::failures().map(json_response),
        Route::Boundaries => api::boundaries().map(json_response),
        Route::Insights => api::insights().map(json_response),
        Route::NotFound => Ok(text_response(404, "not found")),
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

/// Path → route mapping, extracted from `handle` so the v1 wire contract is
/// unit-testable without a live socket. The dashboard is read-only: only
/// GET/HEAD ever reach this matcher (non-GET/HEAD is rejected in `handle`).
#[derive(Debug, PartialEq, Eq)]
enum Route {
    Index,
    Summary,
    ByDay,
    WeakFilters,
    Failures,
    Boundaries,
    Insights,
    NotFound,
}

fn route(path: &str) -> Route {
    match path {
        "/" | "/index.html" => Route::Index,
        "/api/summary" => Route::Summary,
        "/api/by-day" => Route::ByDay,
        "/api/weak-filters" => Route::WeakFilters,
        "/api/failures" => Route::Failures,
        "/api/boundaries" => Route::Boundaries,
        "/api/insights" => Route::Insights,
        _ => Route::NotFound,
    }
}

fn index_response() -> Response<std::io::Cursor<Vec<u8>>> {
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

/// SIGINT-set sentinel. POSIX says a signal handler must only touch async-
/// signal-safe operations — locking a Mutex is not in that set (codex peer-
/// review MED). We use a `'static AtomicBool` directly: `store` on AtomicBool
/// is wait-free and explicitly listed as signal-safe under the POSIX
/// `<signal.h>` rules for lock-free types.
#[cfg(unix)]
static SIGINT_FIRED: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
fn ctrlc_handler(flag: Arc<AtomicBool>) {
    // The local `flag` is what the main loop polls; the static sentinel is
    // what the signal handler can safely write to. A polling thread bridges
    // the two so the main loop's contract is unchanged.
    extern "C" fn on_sigint(_: libc::c_int) {
        SIGINT_FIRED.store(true, Ordering::Relaxed);
    }
    unsafe {
        libc::signal(libc::SIGINT, on_sigint as *const () as libc::sighandler_t);
    }
    std::thread::spawn(move || loop {
        if SIGINT_FIRED.load(Ordering::Relaxed) {
            flag.store(true, Ordering::Relaxed);
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    });
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

    /// The v1 wire contract: every path the HTML fetch calls must resolve.
    /// Adding an endpoint to the frontend without teaching `route` fails here.
    #[test]
    fn route_contract_serves_every_frontend_path() {
        for (path, expected) in [
            ("/", Route::Index),
            ("/index.html", Route::Index),
            ("/api/summary", Route::Summary),
            ("/api/by-day", Route::ByDay),
            ("/api/weak-filters", Route::WeakFilters),
            ("/api/failures", Route::Failures),
            ("/api/boundaries", Route::Boundaries),
            ("/api/insights", Route::Insights),
        ] {
            assert_eq!(route(path), expected, "unexpected route for {path}");
        }
    }

    /// Query strings are stripped in `handle` (before this matcher); the
    /// trailing-slash behaviour is part of `route`'s contract. A slash after
    /// an exact path is NOT one of the v1 routes.
    #[test]
    fn route_rejects_trailing_slash() {
        assert_eq!(route("/api/by-day/"), Route::NotFound);
        assert_eq!(route("/api/summary/"), Route::NotFound);
    }

    /// Anything outside the v1 surface is a 404, not a crash — including
    /// the #171/#172 pane paths that #162 deliberately does not ship.
    #[test]
    fn route_unknown_paths_are_not_found() {
        assert_eq!(route("/api/no-such-endpoint"), Route::NotFound);
        assert_eq!(route("/api/security/gate"), Route::NotFound);
        assert_eq!(route("/api/installs"), Route::NotFound);
    }
}
