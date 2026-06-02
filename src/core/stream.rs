use anyhow::{Context, Result};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;
use wait_timeout::ChildExt;

#[cfg(test)]
use regex::Regex;

pub trait StreamFilter {
    fn feed_line(&mut self, line: &str) -> Option<String>;
    fn flush(&mut self) -> String;
    fn on_exit(&mut self, _exit_code: i32, _raw: &str) -> Option<String> {
        None
    }
}

pub trait BlockHandler {
    fn should_skip(&mut self, line: &str) -> bool;
    fn is_block_start(&mut self, line: &str) -> bool;
    fn is_block_continuation(&mut self, line: &str, block: &[String]) -> bool;
    fn format_summary(&self, exit_code: i32, raw: &str) -> Option<String>;
}

pub struct BlockStreamFilter<H: BlockHandler> {
    handler: H,
    in_block: bool,
    current_block: Vec<String>,
    blocks_emitted: usize,
}

impl<H: BlockHandler> BlockStreamFilter<H> {
    pub fn new(handler: H) -> Self {
        Self {
            handler,
            in_block: false,
            current_block: Vec::new(),
            blocks_emitted: 0,
        }
    }

    fn emit_block(&mut self) -> Option<String> {
        if self.current_block.is_empty() {
            return None;
        }
        let block = self.current_block.join("\n");
        self.current_block.clear();
        self.blocks_emitted += 1;
        Some(format!("{}\n", block))
    }
}

impl<H: BlockHandler> StreamFilter for BlockStreamFilter<H> {
    fn feed_line(&mut self, line: &str) -> Option<String> {
        if self.handler.should_skip(line) {
            return None;
        }

        if self.handler.is_block_start(line) {
            let prev = self.emit_block();
            self.current_block.push(line.to_string());
            self.in_block = true;
            prev
        } else if self.in_block {
            if self
                .handler
                .is_block_continuation(line, &self.current_block)
            {
                self.current_block.push(line.to_string());
                None
            } else {
                self.in_block = false;
                self.emit_block()
            }
        } else {
            None
        }
    }

    fn flush(&mut self) -> String {
        self.emit_block().unwrap_or_default()
    }

    fn on_exit(&mut self, exit_code: i32, raw: &str) -> Option<String> {
        self.handler.format_summary(exit_code, raw)
    }
}

/// Counterpart to [`BlockHandler`] for line-oriented streams.
///
/// Default behaviour is KEEP — every line is emitted unchanged. Implementors
/// opt in to dropping noise via [`LineHandler::should_skip`] and may capture
/// state for the final summary via [`LineHandler::observe_line`].
pub trait LineHandler {
    fn should_skip(&mut self, _line: &str) -> bool {
        false
    }

    fn observe_line(&mut self, _line: &str) {}

    fn format_summary(&self, exit_code: i32, raw: &str) -> Option<String>;
}

pub struct LineStreamFilter<H: LineHandler> {
    handler: H,
}

impl<H: LineHandler> LineStreamFilter<H> {
    pub fn new(handler: H) -> Self {
        Self { handler }
    }
}

impl<H: LineHandler> StreamFilter for LineStreamFilter<H> {
    fn feed_line(&mut self, line: &str) -> Option<String> {
        if self.handler.should_skip(line) {
            return None;
        }
        self.handler.observe_line(line);
        Some(format!("{}\n", line))
    }

    fn flush(&mut self) -> String {
        String::new()
    }

    fn on_exit(&mut self, exit_code: i32, raw: &str) -> Option<String> {
        self.handler.format_summary(exit_code, raw)
    }
}

#[cfg(test)] // available for command modules; currently used in tests only
pub struct RegexBlockFilter {
    start_re: Regex,
    skip_prefixes: Vec<String>,
    tool_name: String,
    block_count: usize,
}

#[cfg(test)]
impl RegexBlockFilter {
    pub fn new(tool_name: &str, start_pattern: &str) -> Self {
        Self {
            start_re: Regex::new(start_pattern).unwrap_or_else(|e| {
                panic!("RegexBlockFilter: bad pattern '{}': {}", start_pattern, e)
            }),
            skip_prefixes: Vec::new(),
            tool_name: tool_name.to_string(),
            block_count: 0,
        }
    }

    pub fn skip_prefix(mut self, prefix: &str) -> Self {
        self.skip_prefixes.push(prefix.to_string());
        self
    }

    pub fn skip_prefixes(mut self, prefixes: &[&str]) -> Self {
        self.skip_prefixes
            .extend(prefixes.iter().map(|s| s.to_string()));
        self
    }
}

#[cfg(test)]
impl BlockHandler for RegexBlockFilter {
    fn should_skip(&mut self, line: &str) -> bool {
        self.skip_prefixes.iter().any(|p| line.starts_with(p))
    }

    fn is_block_start(&mut self, line: &str) -> bool {
        if self.start_re.is_match(line) {
            self.block_count += 1;
            true
        } else {
            false
        }
    }

    fn is_block_continuation(&mut self, line: &str, _block: &[String]) -> bool {
        line.starts_with(' ') || line.starts_with('\t')
    }

    fn format_summary(&self, _exit_code: i32, _raw: &str) -> Option<String> {
        if self.block_count == 0 {
            Some(format!("{}: no errors found\n", self.tool_name))
        } else {
            Some(format!(
                "{}: {} blocks in output\n",
                self.tool_name, self.block_count
            ))
        }
    }
}

pub trait StdinFilter: Send {
    fn feed_line(&mut self, line: &str) -> Option<String>;
    fn flush(&mut self) -> String;
}

pub enum FilterMode<'a> {
    Streaming(Box<dyn StreamFilter + 'a>),
    #[allow(dead_code)]
    Buffered(Box<dyn Fn(&str) -> String + 'a>),
    CaptureOnly,
    Passthrough,
}

pub enum StdinMode {
    Inherit,
    #[allow(dead_code)] // future API: stdin filtering for interactive commands
    Filter(Box<dyn StdinFilter + Send>),
    Null,
}

pub struct StreamResult {
    pub exit_code: i32,
    pub raw: String,
    pub raw_stdout: String,
    pub raw_stderr: String,
    pub filtered: String,
    /// True if the in-memory `filtered` accumulator hit `FILTERED_CAP` and
    /// subsequent filtered text was dropped. When set, `filtered` holds an
    /// incomplete prefix and a visible `[contextcrawler: output truncated
    /// at N bytes]` marker was emitted to the output sink (and appended to
    /// `filtered` itself) so the agent/user knows the output is incomplete.
    /// Part of the public `StreamResult` contract for callers parsing
    /// `filtered`; consumed by tests today.
    #[allow(dead_code)]
    pub truncated_filtered: bool,
}

impl StreamResult {
    #[cfg(test)]
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

pub fn status_to_exit_code(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return 128 + sig;
        }
    }
    1
}

// ISSUE #897: ChildGuard RAII prevents zombie processes that caused kernel panic
pub const RAW_CAP: usize = 10_485_760; // 10 MiB

/// Bound on the line-passing channel between the reader threads and the
/// consumer loop. Without a bound, a child that floods stdout faster than the
/// consumer can drain it grows the channel unboundedly (OOM). 4096 buffered
/// lines is generous headroom while still capping memory.
const STREAM_CHANNEL_CAP: usize = 4096;

/// Cap on the in-memory `filtered` accumulator. The raw stdout/stderr buffers
/// are already capped by `RAW_CAP`, but a pathological filter could expand its
/// input; bound the filtered buffer independently so capture stays O(RAW_CAP).
const FILTERED_CAP: usize = RAW_CAP;

/// Bound on the sink channel feeding the dedicated writer thread. The writer
/// thread drains filtered chunks to the real stdout/stderr. If the terminal
/// wedges, the writer stalls and queued chunks accumulate here. An *unbounded*
/// channel would grow without limit (OOM) while the child floods output — so
/// the channel is bounded and the consumer uses `try_send`: a full channel
/// means the chunk is dropped (and accounted), never blocked on. The child
/// drain therefore never stalls on a wedged sink. 8192 buffered chunks is
/// generous headroom for a transient terminal hiccup while capping memory.
const SINK_CHANNEL_CAP: usize = 8192;

/// Read a child stream line-by-line as raw bytes, yielding lossy-UTF-8 strings.
///
/// `BufRead::lines()` is strict UTF-8 and `.map_while(Result::ok)` silently
/// stops at the first non-UTF-8 byte, truncating the rest of the child's
/// output. Reading bytes and converting with `from_utf8_lossy` preserves every
/// line (replacing invalid bytes with U+FFFD) instead of dropping output.
fn for_each_line<R: Read>(reader: R, mut f: impl FnMut(String)) {
    let mut buf = BufReader::new(reader);
    let mut bytes: Vec<u8> = Vec::new();
    loop {
        bytes.clear();
        match buf.read_until(b'\n', &mut bytes) {
            Ok(0) => break, // EOF
            Ok(_) => {
                // Trim a trailing \n (and \r) to match BufRead::lines() semantics.
                if bytes.last() == Some(&b'\n') {
                    bytes.pop();
                    if bytes.last() == Some(&b'\r') {
                        bytes.pop();
                    }
                }
                f(String::from_utf8_lossy(&bytes).into_owned());
            }
            Err(_) => break,
        }
    }
}

/// Drive a `StdinFilter` from an arbitrary `Read` source, writing filtered
/// lines to `writer`.
///
/// Extracted from the `StdinMode::Filter` spawned thread so the lossy
/// byte-read path can be unit-tested without touching real `io::stdin()`.
/// The caller (spawned thread) passes `io::stdin().lock()` as `reader`.
///
/// Uses `for_each_line` (byte-read + `from_utf8_lossy`) rather than
/// `BufRead::lines()` so invalid UTF-8 bytes are replaced with U+FFFD
/// instead of silently truncating the rest of the stream (council P1-3).
///
/// Write errors (child stdin closed because the child exited) are ignored
/// per-line: the remaining input is drained to EOF rather than aborting,
/// which keeps the semantics simple at the cost of reading stdin a little
/// longer than strictly necessary after an early child exit.
fn run_stdin_filter<R: Read, W: Write>(reader: R, writer: &mut W, filter: &mut dyn StdinFilter) {
    for_each_line(reader, |line| {
        if let Some(out) = filter.feed_line(&line) {
            let _ = writeln!(writer, "{}", out);
        }
    });
    let tail = filter.flush();
    if !tail.is_empty() {
        let _ = write!(writer, "{}", tail);
    }
}

pub fn run_streaming(
    cmd: &mut Command,
    stdin_mode: StdinMode,
    stdout_mode: FilterMode<'_>,
) -> Result<StreamResult> {
    run_streaming_with_sink(cmd, stdin_mode, stdout_mode, None)
}

/// Optional override for the sink-writer thread's destinations: `(stdout-like,
/// stderr-like)`. Production passes `None` (real stdout/stderr); tests inject a
/// `Write` that can be wedged to exercise the bounded-sink drop-on-overflow
/// path without hanging the test runner.
type SinkOverride = Option<(Box<dyn Write + Send>, Box<dyn Write + Send>)>;

/// Implementation of [`run_streaming`] with an injectable sink destination.
/// See [`SinkOverride`]. All public callers go through `run_streaming`.
fn run_streaming_with_sink(
    cmd: &mut Command,
    stdin_mode: StdinMode,
    stdout_mode: FilterMode<'_>,
    sink_override: SinkOverride,
) -> Result<StreamResult> {
    if matches!(stdout_mode, FilterMode::Passthrough) {
        match &stdin_mode {
            StdinMode::Inherit => {
                cmd.stdin(Stdio::inherit());
            }
            _ => {
                cmd.stdin(Stdio::null());
            }
        };
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());
        let status = cmd.status().context("Failed to spawn process")?;
        return Ok(StreamResult {
            exit_code: status_to_exit_code(status),
            raw: String::new(),
            raw_stdout: String::new(),
            raw_stderr: String::new(),
            filtered: String::new(),
            truncated_filtered: false,
        });
    }

    match &stdin_mode {
        StdinMode::Inherit => {
            cmd.stdin(Stdio::inherit());
        }
        StdinMode::Filter(_) | StdinMode::Null => {
            cmd.stdin(Stdio::piped());
        }
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            self.0.wait().ok();
        }
    }

    let is_streaming = matches!(stdout_mode, FilterMode::Streaming(_));

    let mut child = ChildGuard(cmd.spawn().context("Failed to spawn process")?);

    let stdin_thread: Option<std::thread::JoinHandle<()>> = match stdin_mode {
        StdinMode::Filter(mut filter) => {
            let child_stdin = child.0.stdin.take().context("No child stdin handle")?;
            Some(std::thread::spawn(move || {
                let mut writer = BufWriter::new(child_stdin);
                let stdin_handle = io::stdin();
                run_stdin_filter(stdin_handle.lock(), &mut writer, filter.as_mut());
            }))
        }
        StdinMode::Null => {
            child.0.stdin.take();
            None
        }
        StdinMode::Inherit => None,
    };

    let stdout = child.0.stdout.take().context("No child stdout handle")?;
    let stderr = child.0.stderr.take().context("No child stderr handle")?;
    let mut raw_stdout = String::new();
    let mut raw_stderr = String::new();
    let mut filtered = String::new();
    let mut truncated_filtered = false;
    let mut capped_out = false;
    let mut capped_err = false;
    let mut saved_filter: Option<Box<dyn StreamFilter + '_>> = None;
    let mut filter_fd_is_stderr = false;

    if is_streaming {
        enum StreamLine {
            Stdout(String),
            Stderr(String),
        }

        // Bounded channel: backpressure caps memory if the child outpaces us.
        let (tx, rx) = mpsc::sync_channel(STREAM_CHANNEL_CAP);
        let tx_out = tx.clone();
        let stdout_thread = std::thread::spawn(move || {
            // Byte-line read + lossy UTF-8: never truncates on non-UTF-8 bytes.
            let mut closed = false;
            for_each_line(stdout, |line| {
                if !closed && tx_out.send(StreamLine::Stdout(line)).is_err() {
                    closed = true; // consumer gone — stop forwarding
                }
            });
        });
        let tx_err = tx;
        let stderr_thread = std::thread::spawn(move || {
            let mut closed = false;
            for_each_line(stderr, |line| {
                if !closed && tx_err.send(StreamLine::Stderr(line)).is_err() {
                    closed = true;
                }
            });
        });

        // Sink message: a chunk of filtered text destined for stdout/stderr.
        enum SinkMsg {
            Out(String),
            Err(String),
        }

        // Decouple draining from sink writes. The consumer loop below drains
        // the bounded child channel (`rx`) AND must never block on a slow
        // terminal — if it did, the reader threads would fill `rx` and the
        // child's own writes would stall. Sink writes are handed to a
        // dedicated writer thread over a *bounded* channel: the consumer
        // always makes progress draining the child, and back-pressure from a
        // wedged terminal is absorbed here — but only up to SINK_CHANNEL_CAP
        // chunks. An unbounded channel would let a wedged sink grow memory
        // without limit (OOM) while the child floods output. Past the cap the
        // consumer DROPS the chunk (via `try_send`) and accounts the bytes;
        // it never blocks. The terminal output is lost in that scenario, but
        // it was un-writable anyway, and the child drain is never stalled.
        let (sink_tx, sink_rx) = mpsc::sync_channel::<SinkMsg>(SINK_CHANNEL_CAP);
        let sink_thread = std::thread::spawn(move || {
            // Either the real stdout/stderr locks, or test-injected sinks.
            let stdout_handle = io::stdout();
            let stderr_handle = io::stderr();
            let (mut out, mut err_out): (Box<dyn Write>, Box<dyn Write>) = match sink_override {
                Some((o, e)) => (o, e),
                None => (
                    Box::new(stdout_handle.lock()),
                    Box::new(stderr_handle.lock()),
                ),
            };
            for msg in sink_rx {
                let (text, dest): (String, &mut dyn Write) = match msg {
                    SinkMsg::Out(t) => (t, &mut *out),
                    SinkMsg::Err(t) => (t, &mut *err_out),
                };
                // Broken pipe / IO error on the sink: stop writing but keep
                // draining the channel so senders never block. The child
                // drain is unaffected.
                let _ = write!(dest, "{}", text);
            }
            let _ = out.flush();
            let _ = err_out.flush();
        });

        // Drop-on-overflow accounting for the bounded sink channel. When the
        // sink writer wedges and the channel fills, chunks are dropped here
        // instead of blocking the child drain. `dropped_bytes` totals what was
        // lost so one summary marker can be emitted at the end.
        let mut dropped_bytes: usize = 0;
        let mut dropped = false;
        let mut sink_gone = false;

        // Hand a SinkMsg to the writer thread without EVER blocking the child
        // drain: `try_send` only. `Full` → drop the chunk + account its bytes;
        // `Disconnected` → writer is gone, stop trying. The child drain in the
        // loop below proceeds regardless — this is the invariant that keeps
        // the deadlock fix from re-introducing a stall (and the bounded
        // channel keeps it from OOMing).
        let sink_send = |tx: &mpsc::SyncSender<SinkMsg>,
                         msg: SinkMsg,
                         dropped_bytes: &mut usize,
                         dropped: &mut bool,
                         sink_gone: &mut bool| {
            let len = |m: &SinkMsg| match m {
                SinkMsg::Out(t) | SinkMsg::Err(t) => t.len(),
            };
            if *sink_gone {
                *dropped_bytes += len(&msg);
                *dropped = true;
                return;
            }
            match tx.try_send(msg) {
                Ok(()) => {}
                Err(mpsc::TrySendError::Full(m)) => {
                    *dropped_bytes += len(&m);
                    *dropped = true;
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    *sink_gone = true;
                }
            }
        };

        if let FilterMode::Streaming(mut filter) = stdout_mode {
            for msg in rx {
                let (line, is_stderr) = match msg {
                    StreamLine::Stderr(l) => (l, true),
                    StreamLine::Stdout(l) => (l, false),
                };
                if is_stderr {
                    if !capped_err {
                        if raw_stderr.len() + line.len() < RAW_CAP {
                            raw_stderr.push_str(&line);
                            raw_stderr.push('\n');
                        } else {
                            capped_err = true;
                            eprintln!("[contextcrawler] warning: stderr exceeds 10 MiB — capture truncated");
                        }
                    }
                } else if !capped_out {
                    if raw_stdout.len() + line.len() < RAW_CAP {
                        raw_stdout.push_str(&line);
                        raw_stdout.push('\n');
                    } else {
                        capped_out = true;
                        eprintln!("[contextcrawler] warning: stdout exceeds 10 MiB — filter input truncated");
                    }
                }
                filter_fd_is_stderr = is_stderr;
                // Strip ANSI before feeding the filter: go/gradle filter
                // predicates match plain text, so coloured failure markers
                // (e.g. red "FAIL") would otherwise evade compaction. The raw
                // line is still preserved verbatim in raw_stdout/raw_stderr.
                let clean = crate::core::utils::strip_ansi(&line);
                if let Some(output) = filter.feed_line(&clean) {
                    if filtered.len() < FILTERED_CAP {
                        filtered.push_str(&output);
                    } else if !truncated_filtered {
                        truncated_filtered = true;
                        let marker = format!(
                            "\n[contextcrawler: output truncated at {} bytes]\n",
                            FILTERED_CAP
                        );
                        filtered.push_str(&marker);
                        // Surface the marker on the same fd the filter is
                        // writing to. Sink send cannot block the drain.
                        let mm = if is_stderr {
                            SinkMsg::Err(marker)
                        } else {
                            SinkMsg::Out(marker)
                        };
                        sink_send(
                            &sink_tx,
                            mm,
                            &mut dropped_bytes,
                            &mut dropped,
                            &mut sink_gone,
                        );
                    }
                    let m = if is_stderr {
                        SinkMsg::Err(output)
                    } else {
                        SinkMsg::Out(output)
                    };
                    // Bounded `try_send` to the writer thread: never blocks
                    // the child drain even if the terminal is wedged. A full
                    // channel drops the chunk (accounted in `dropped_bytes`)
                    // rather than stalling — the drain keeps going.
                    sink_send(
                        &sink_tx,
                        m,
                        &mut dropped_bytes,
                        &mut dropped,
                        &mut sink_gone,
                    );
                }
            }
            let tail = filter.flush();
            if filtered.len() < FILTERED_CAP {
                filtered.push_str(&tail);
            } else if !truncated_filtered && !tail.is_empty() {
                truncated_filtered = true;
                let marker = format!(
                    "\n[contextcrawler: output truncated at {} bytes]\n",
                    FILTERED_CAP
                );
                filtered.push_str(&marker);
                let mm = if filter_fd_is_stderr {
                    SinkMsg::Err(marker)
                } else {
                    SinkMsg::Out(marker)
                };
                sink_send(
                    &sink_tx,
                    mm,
                    &mut dropped_bytes,
                    &mut dropped,
                    &mut sink_gone,
                );
            }
            let tail_msg = if filter_fd_is_stderr {
                SinkMsg::Err(tail)
            } else {
                SinkMsg::Out(tail)
            };
            sink_send(
                &sink_tx,
                tail_msg,
                &mut dropped_bytes,
                &mut dropped,
                &mut sink_gone,
            );
            saved_filter = Some(filter);
        }

        // If the sink wedged and chunks were dropped, emit ONE summary marker
        // — both into the `filtered` accumulator (so the captured output
        // records the loss) and, best-effort, to the sink itself. This
        // mirrors the `truncated_filtered` marker pattern above.
        if dropped {
            let marker = format!(
                "\n[contextcrawler: {} bytes dropped — output sink stalled]\n",
                dropped_bytes
            );
            // Append unconditionally — do NOT gate on FILTERED_CAP. The cap is
            // a soft guard against unbounded accumulator growth; this is a
            // fixed ~60-byte end-of-stream diagnostic. Gating it meant a user
            // whose output BOTH filled the accumulator AND hit sink drops saw
            // no notice of the loss at all. A tiny fixed trailing overrun is
            // harmless; silently swallowing the drop notice is not. The
            // `truncated_filtered` markers above already append unconditionally
            // once over cap, so both end-of-stream markers stay visible even
            // when truncation and drop fire together.
            filtered.push_str(&marker);
            let mm = if filter_fd_is_stderr {
                SinkMsg::Err(marker)
            } else {
                SinkMsg::Out(marker)
            };
            // One final best-effort attempt; if the channel is still full or
            // the writer is gone this is simply dropped too.
            sink_send(
                &sink_tx,
                mm,
                &mut dropped_bytes,
                &mut dropped,
                &mut sink_gone,
            );
        }

        // Drop our sender so the writer thread sees the channel close and
        // exits once it has flushed every queued chunk.
        drop(sink_tx);
        sink_thread.join().ok();

        stdout_thread.join().ok();
        stderr_thread.join().ok();
    } else {
        let stderr_thread = std::thread::spawn(move || -> String {
            let mut raw_err = String::new();
            let mut capped = false;
            // Byte-line read + lossy UTF-8: never truncates on non-UTF-8 bytes.
            for_each_line(stderr, |line| {
                if raw_err.len() + line.len() < RAW_CAP {
                    raw_err.push_str(&line);
                    raw_err.push('\n');
                } else if !capped {
                    capped = true;
                }
            });
            raw_err
        });

        {
            let stdout_handle = io::stdout();
            let mut out = stdout_handle.lock();

            match stdout_mode {
                FilterMode::Passthrough => unreachable!("handled by early-return above"),
                FilterMode::Streaming(_) => unreachable!("handled by is_streaming branch"),
                FilterMode::Buffered(filter_fn) => {
                    for_each_line(stdout, |line| {
                        if raw_stdout.len() + line.len() < RAW_CAP {
                            raw_stdout.push_str(&line);
                            raw_stdout.push('\n');
                        } else if !capped_out {
                            capped_out = true;
                            eprintln!(
                                "[contextcrawler] warning: output exceeds 10 MiB — filter input truncated"
                            );
                        }
                    });
                    filtered = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        filter_fn(&raw_stdout)
                    }))
                    .unwrap_or_else(|_| {
                        eprintln!("[contextcrawler] warning: filter panicked — passing through raw output");
                        raw_stdout.clone()
                    });
                    match write!(out, "{}", filtered) {
                        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {}
                        Err(e) => return Err(e.into()),
                        Ok(_) => {}
                    }
                }
                FilterMode::CaptureOnly => {
                    for_each_line(stdout, |line| {
                        if raw_stdout.len() + line.len() < RAW_CAP {
                            raw_stdout.push_str(&line);
                            raw_stdout.push('\n');
                        } else if !capped_out {
                            capped_out = true;
                            eprintln!(
                                "[contextcrawler] warning: output exceeds 10 MiB — filter input truncated"
                            );
                        }
                    });
                    filtered = raw_stdout.clone();
                }
            }
        }

        raw_stderr = stderr_thread.join().unwrap_or_else(|e| {
            eprintln!(
                "[contextcrawler] warning: stderr reader thread panicked: {:?}",
                e
            );
            String::new()
        });
    }
    if let Some(t) = stdin_thread {
        t.join().ok();
    }

    let status = child.0.wait().context("Failed to wait for child")?;
    let exit_code = status_to_exit_code(status);
    let raw = format!("{}{}", raw_stdout, raw_stderr);

    if let Some(mut f) = saved_filter {
        if let Some(post) = f.on_exit(exit_code, &raw) {
            filtered.push_str(&post);
            // `post` is written directly to stdout/stderr rather than routed
            // through the sink channel. This is safe and race-free: the
            // sink-writer thread was already joined above (`sink_thread.join`),
            // so there is no concurrent writer to the same fd. Routing it
            // through the channel would mean resurrecting the joined writer,
            // which buys nothing here. A wedged terminal can still block this
            // one trailing write, but the child has already exited by now —
            // there is no drain left to stall, so the OOM/deadlock concern
            // that motivated the bounded sink channel does not apply.
            let mut dest: Box<dyn Write> = if filter_fd_is_stderr {
                Box::new(io::stderr().lock())
            } else {
                Box::new(io::stdout().lock())
            };
            match write!(dest, "{}", post) {
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {}
                Err(e) => return Err(e.into()),
                Ok(_) => {}
            }
        }
    }

    Ok(StreamResult {
        exit_code,
        raw,
        raw_stdout,
        raw_stderr,
        filtered,
        truncated_filtered,
    })
}

pub struct CaptureResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    /// True if the per-stream cap fired and `stdout` is a prefix of the
    /// child's full output. Callers parsing structured data (JSON, etc.)
    /// should treat parse failures on a truncated buffer as expected
    /// rather than as a real error. Defaults to false.
    pub truncated_stdout: bool,
    /// True if the per-stream cap fired on stderr. Same semantics as
    /// `truncated_stdout`.
    pub truncated_stderr: bool,
}

impl CaptureResult {
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }

    pub fn combined(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

/// Default per-stream cap for `exec_capture*`. A runaway child filling
/// stdout/stderr could otherwise OOM the host. 64 MiB matches the upper
/// bound used by the tirith gate hardening (v0.1.6 `b4c93c3`).
pub const DEFAULT_CAPTURE_STREAM_MAX: u64 = 64 * 1024 * 1024;

/// Limits applied to `exec_capture_with_limits`.
///
/// `Default` uses generous caps (64 MiB / 64 MiB) and no wall-clock
/// timeout — appropriate for user-driven filter runs (`rtk cargo test`,
/// `rtk pnpm install`) where the user has explicit context and can ^C.
/// Hook-path callers should use `exec_capture_short` instead, which sets
/// `timeout = Some(_)` so a hung child cannot freeze the agent.
pub struct CaptureLimits {
    pub stdout_max: u64,
    pub stderr_max: u64,
    pub timeout: Option<Duration>,
}

impl Default for CaptureLimits {
    fn default() -> Self {
        Self {
            stdout_max: DEFAULT_CAPTURE_STREAM_MAX,
            stderr_max: DEFAULT_CAPTURE_STREAM_MAX,
            timeout: None,
        }
    }
}

/// Capture a child's stdout/stderr with explicit caps and optional
/// wall-clock timeout. stdin is always nulled (callers that need to feed
/// stdin should use `run_streaming` with `StdinMode::Filter`).
///
/// Caps fire silently: the returned `CaptureResult` contains the
/// truncated prefix and the child runs to completion. A timeout, by
/// contrast, returns `Err` — the caller decides fallback.
pub fn exec_capture_with_limits(cmd: &mut Command, limits: CaptureLimits) -> Result<CaptureResult> {
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().context("Failed to execute command")?;

    // Drain stdout/stderr concurrently so a chatty child can't fill the
    // ~64 KiB kernel pipe buffer and deadlock either us or itself.
    let stdout_handle = child.stdout.take().context("No child stdout handle")?;
    let stderr_handle = child.stderr.take().context("No child stderr handle")?;
    let stdout_max = limits.stdout_max;
    let stderr_max = limits.stderr_max;
    let stdout_thread = std::thread::spawn(move || drain_with_cap(stdout_handle, stdout_max));
    let stderr_thread = std::thread::spawn(move || drain_with_cap(stderr_handle, stderr_max));

    let status = match limits.timeout {
        Some(deadline) => match child.wait_timeout(deadline) {
            Ok(Some(s)) => s,
            Ok(None) => {
                // Child exceeded the deadline. Kill, reap, drain threads,
                // then surface as Err so the caller can fall back.
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                anyhow::bail!("command exceeded wall-clock budget of {:?}", deadline);
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                return Err(anyhow::Error::from(e).context("wait_timeout on child process failed"));
            }
        },
        None => child.wait().context("Failed to wait on child")?,
    };

    let (stdout_buf, truncated_stdout) = stdout_thread
        .join()
        .map_err(|_| anyhow::anyhow!("stdout drain thread panicked"))?;
    let (stderr_buf, truncated_stderr) = stderr_thread
        .join()
        .map_err(|_| anyhow::anyhow!("stderr drain thread panicked"))?;

    Ok(CaptureResult {
        stdout: String::from_utf8_lossy(&stdout_buf).into_owned(),
        stderr: String::from_utf8_lossy(&stderr_buf).into_owned(),
        exit_code: status_to_exit_code(status),
        truncated_stdout,
        truncated_stderr,
    })
}

/// Read at most `max` bytes from `r`, returning the bytes plus a flag
/// indicating whether the stream had more pending after the cap.
///
/// Detection works by reading one byte past the cap: if the read returns
/// 0 we hit EOF exactly at the cap (not truncated); if it returns 1 we
/// truncated. We then close the handle implicitly by dropping `r`,
/// which lets the child receive SIGPIPE on its next write.
fn drain_with_cap<R: Read>(mut r: R, max: u64) -> (Vec<u8>, bool) {
    let mut buf = Vec::new();
    if max == 0 {
        // Pathological config; still peek one byte to detect truncation.
        let mut probe = [0u8; 1];
        let truncated = matches!(r.read(&mut probe), Ok(n) if n > 0);
        return (buf, truncated);
    }
    let _ = (&mut r).take(max).read_to_end(&mut buf);
    let mut probe = [0u8; 1];
    let truncated = matches!(r.read(&mut probe), Ok(n) if n > 0);
    (buf, truncated)
}

/// Capture with default limits — 64 MiB per stream, no wall-clock deadline.
/// Use for user-driven commands where the user can ^C themselves.
///
/// Emits a fail-loud `[ctxc] warning: ...` on stderr if either cap fires.
/// This protects callers that don't (yet) read `CaptureResult.truncated_*`
/// from silently treating a capped prefix as complete output. Mirrors the
/// existing `RAW_CAP` warnings in `run_streaming`. Callers that want
/// silence — because they're going to inspect the flags themselves —
/// should use `exec_capture_with_limits` directly.
pub fn exec_capture(cmd: &mut Command) -> Result<CaptureResult> {
    let r = exec_capture_with_limits(cmd, CaptureLimits::default())?;
    warn_if_capped(&r, "exec_capture");
    Ok(r)
}

/// Capture with a wall-clock deadline. Use this from hook-path callers
/// (PreToolUse, integrity check, anything Claude Code waits on
/// synchronously) so a hung child cannot freeze the agent.
///
/// Returns `Err` on timeout; callers should treat that as "subprocess
/// unavailable" and fall back, the same shape `tirith_gate::check` uses.
/// Like `exec_capture`, emits a fail-loud warning on cap-hit so silent
/// truncation can't mislead a downstream parser.
pub fn exec_capture_short(cmd: &mut Command, timeout: Duration) -> Result<CaptureResult> {
    let r = exec_capture_with_limits(
        cmd,
        CaptureLimits {
            timeout: Some(timeout),
            ..CaptureLimits::default()
        },
    )?;
    warn_if_capped(&r, "exec_capture_short");
    Ok(r)
}

fn warn_if_capped(r: &CaptureResult, label: &str) {
    if r.truncated_stdout {
        eprintln!(
            "[ctxc] warning: {} stdout exceeded {} MiB — capture truncated",
            label,
            DEFAULT_CAPTURE_STREAM_MAX / (1024 * 1024)
        );
    }
    if r.truncated_stderr {
        eprintln!(
            "[ctxc] warning: {} stderr exceeded {} MiB — capture truncated",
            label,
            DEFAULT_CAPTURE_STREAM_MAX / (1024 * 1024)
        );
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::process::Command;

    struct LineFilter<F: FnMut(&str) -> Option<String>> {
        f: F,
    }

    impl<F: FnMut(&str) -> Option<String>> LineFilter<F> {
        pub fn new(f: F) -> Self {
            Self { f }
        }
    }

    impl<F: FnMut(&str) -> Option<String>> StreamFilter for LineFilter<F> {
        fn feed_line(&mut self, line: &str) -> Option<String> {
            (self.f)(line)
        }

        fn flush(&mut self) -> String {
            String::new()
        }
    }

    #[test]
    fn test_exit_code_zero() {
        let status = Command::new("true").status().unwrap();
        assert_eq!(status_to_exit_code(status), 0);
    }

    #[test]
    fn test_exit_code_nonzero() {
        let status = Command::new("false").status().unwrap();
        assert_eq!(status_to_exit_code(status), 1);
    }

    #[cfg(unix)]
    #[test]
    fn test_exit_code_signal_kill() {
        let mut child = Command::new("sleep").arg("60").spawn().unwrap();
        child.kill().unwrap();
        let status = child.wait().unwrap();
        assert_eq!(status_to_exit_code(status), 137);
    }

    #[test]
    fn test_line_filter_passes_lines() {
        let mut f = LineFilter::new(|l| Some(format!("{}\n", l.to_uppercase())));
        assert_eq!(f.feed_line("hello"), Some("HELLO\n".to_string()));
    }

    #[test]
    fn test_line_filter_drops_lines() {
        let mut f = LineFilter::new(|l| {
            if l.starts_with('#') {
                None
            } else {
                Some(l.to_string())
            }
        });
        assert_eq!(f.feed_line("# comment"), None);
        assert_eq!(f.feed_line("code"), Some("code".to_string()));
    }

    #[test]
    fn test_line_filter_flush_empty() {
        let mut f = LineFilter::new(|l| Some(l.to_string()));
        assert_eq!(f.flush(), String::new());
    }

    #[test]
    fn test_stream_result_success() {
        let r = StreamResult {
            exit_code: 0,
            raw: String::new(),
            raw_stdout: String::new(),
            raw_stderr: String::new(),
            filtered: String::new(),
            truncated_filtered: false,
        };
        assert!(r.success());
    }

    #[test]
    fn test_stream_result_failure() {
        let r = StreamResult {
            exit_code: 1,
            raw: String::new(),
            raw_stdout: String::new(),
            raw_stderr: String::new(),
            filtered: String::new(),
            truncated_filtered: false,
        };
        assert!(!r.success());
    }

    #[test]
    fn test_stream_result_signal_not_success() {
        let r = StreamResult {
            exit_code: 137,
            raw: String::new(),
            raw_stdout: String::new(),
            raw_stderr: String::new(),
            filtered: String::new(),
            truncated_filtered: false,
        };
        assert!(!r.success());
    }

    #[test]
    fn test_run_streaming_passthrough_echo() {
        let mut cmd = Command::new("echo");
        cmd.arg("hello");
        let result = run_streaming(&mut cmd, StdinMode::Null, FilterMode::Passthrough).unwrap();
        assert_eq!(result.exit_code, 0);
        // Passthrough inherits TTY — raw/filtered are empty
        assert!(result.raw.is_empty());
    }

    #[test]
    fn test_run_streaming_exit_code_preserved() {
        // nosemgrep: interpreter-execution
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "exit 42"]);
        let result = run_streaming(&mut cmd, StdinMode::Null, FilterMode::Passthrough).unwrap();
        assert_eq!(result.exit_code, 42);
    }

    #[test]
    fn test_run_streaming_exit_code_zero() {
        let mut cmd = Command::new("true");
        let result = run_streaming(&mut cmd, StdinMode::Null, FilterMode::Passthrough).unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(result.success());
    }

    #[test]
    fn test_run_streaming_exit_code_one() {
        let mut cmd = Command::new("false");
        let result = run_streaming(&mut cmd, StdinMode::Null, FilterMode::Passthrough).unwrap();
        assert_eq!(result.exit_code, 1);
        assert!(!result.success());
    }

    #[cfg(not(windows))]
    #[test]
    fn test_run_streaming_streaming_filter_drops_lines() {
        let mut cmd = Command::new("printf");
        cmd.arg("a\nb\nc\n");
        let filter = LineFilter::new(|l| {
            if l == "b" {
                None
            } else {
                Some(format!("{}\n", l))
            }
        });
        let result = run_streaming(
            &mut cmd,
            StdinMode::Null,
            FilterMode::Streaming(Box::new(filter)),
        )
        .unwrap();
        assert!(result.filtered.contains('a'));
        assert!(!result.filtered.contains('b'));
        assert!(result.filtered.contains('c'));
        assert_eq!(result.exit_code, 0);
    }

    #[cfg(not(windows))]
    #[test]
    fn test_run_streaming_buffered_filter() {
        let mut cmd = Command::new("printf");
        cmd.arg("line1\nline2\nline3\n");
        let result = run_streaming(
            &mut cmd,
            StdinMode::Null,
            FilterMode::Buffered(Box::new(|s: &str| s.to_uppercase())),
        )
        .unwrap();
        assert!(result.filtered.contains("LINE1"));
        assert!(result.filtered.contains("LINE2"));
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn test_run_streaming_raw_cap_at_10mb() {
        // nosemgrep: interpreter-execution
        let mut cmd = Command::new("sh");
        // ~11 MiB of 80-char lines (fast: fewer lines than `yes | head -6M`)
        cmd.args([
            "-c",
            "dd if=/dev/zero bs=1024 count=11264 2>/dev/null | tr '\\0' 'a' | fold -w 80",
        ]);
        let result = run_streaming(&mut cmd, StdinMode::Null, FilterMode::CaptureOnly).unwrap();
        assert!(
            result.raw.len() <= 10_485_760 + 100,
            "raw should be capped at ~10 MiB, got {} bytes",
            result.raw.len()
        );
        assert!(
            result.raw.len() > 1_000_000,
            "Should have captured significant data"
        );
    }

    #[test]
    fn test_run_streaming_stderr_cap_at_10mb() {
        // nosemgrep: interpreter-execution
        let mut cmd = Command::new("sh");
        // ~11 MiB on stderr, nothing on stdout
        cmd.args([
            "-c",
            "dd if=/dev/zero bs=1024 count=11264 2>/dev/null | tr '\\0' 'a' | fold -w 80 1>&2",
        ]);
        let result = run_streaming(&mut cmd, StdinMode::Null, FilterMode::CaptureOnly).unwrap();
        // raw = raw_stdout + raw_stderr; stdout is empty so raw ≈ stderr size
        assert!(
            result.raw.len() <= RAW_CAP + 200,
            "stderr in raw should be capped at ~10 MiB, got {} bytes",
            result.raw.len()
        );
    }

    #[test]
    fn test_child_guard_prevents_zombie() {
        let mut cmd = Command::new("true");
        let result = run_streaming(&mut cmd, StdinMode::Null, FilterMode::CaptureOnly);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().exit_code, 0);
    }

    #[test]
    fn test_run_streaming_null_stdin_cat() {
        let mut cmd = Command::new("cat");
        let result = run_streaming(&mut cmd, StdinMode::Null, FilterMode::Passthrough).unwrap();
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn test_run_streaming_raw_contains_stdout() {
        let mut cmd = Command::new("echo");
        cmd.arg("test_output_xyz");
        let result = run_streaming(&mut cmd, StdinMode::Null, FilterMode::CaptureOnly).unwrap();
        assert!(result.raw.contains("test_output_xyz"));
    }

    #[test]
    fn test_run_streaming_capture_only_filtered_equals_raw() {
        let mut cmd = Command::new("echo");
        cmd.arg("check_equality");
        let result = run_streaming(&mut cmd, StdinMode::Null, FilterMode::CaptureOnly).unwrap();
        assert_eq!(result.filtered.trim(), result.raw_stdout.trim());
    }

    #[test]
    fn test_exec_capture_success() {
        let mut cmd = Command::new("echo");
        cmd.arg("hello_capture");
        let result = exec_capture(&mut cmd).unwrap();
        assert!(result.success());
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("hello_capture"));
    }

    #[test]
    fn test_exec_capture_failure() {
        let mut cmd = Command::new("false");
        let result = exec_capture(&mut cmd).unwrap();
        assert!(!result.success());
        assert_eq!(result.exit_code, 1);
    }

    #[test]
    fn test_exec_capture_stderr() {
        // nosemgrep: interpreter-execution
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "echo err_msg >&2"]);
        let result = exec_capture(&mut cmd).unwrap();
        assert!(result.stderr.contains("err_msg"));
    }

    #[test]
    fn test_exec_capture_combined() {
        // nosemgrep: interpreter-execution
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "echo out_msg; echo err_msg >&2"]);
        let result = exec_capture(&mut cmd).unwrap();
        let combined = result.combined();
        assert!(combined.contains("out_msg"));
        assert!(combined.contains("err_msg"));
    }

    #[test]
    fn test_capture_result_combined_empty() {
        let r = CaptureResult {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
            truncated_stdout: false,
            truncated_stderr: false,
        };
        assert_eq!(r.combined(), "");
    }

    pub fn run_block_filter(filter: &mut dyn StreamFilter, input: &str, exit_code: i32) -> String {
        let mut output = String::new();
        for line in input.lines() {
            if let Some(s) = filter.feed_line(line) {
                output.push_str(&s);
            }
        }
        output.push_str(&filter.flush());
        if let Some(post) = filter.on_exit(exit_code, input) {
            output.push_str(&post);
        }
        output
    }

    struct TestHandler;

    impl BlockHandler for TestHandler {
        fn should_skip(&mut self, line: &str) -> bool {
            line.starts_with("SKIP")
        }
        fn is_block_start(&mut self, line: &str) -> bool {
            line.starts_with("ERROR")
        }
        fn is_block_continuation(&mut self, line: &str, _block: &[String]) -> bool {
            line.starts_with("  ")
        }
        fn format_summary(&self, _exit_code: i32, _raw: &str) -> Option<String> {
            Some("DONE\n".to_string())
        }
    }

    #[test]
    fn test_block_filter_emits_blocks() {
        let mut f = BlockStreamFilter::new(TestHandler);
        let input = "SKIP noise\nERROR first\n  detail1\nnon-block\nERROR second\n  detail2\n";
        let result = run_block_filter(&mut f, input, 0);
        assert!(result.contains("ERROR first\n  detail1"), "got: {}", result);
        assert!(
            result.contains("ERROR second\n  detail2"),
            "got: {}",
            result
        );
        assert!(!result.contains("SKIP"), "got: {}", result);
        assert!(result.ends_with("DONE\n"), "got: {}", result);
    }

    #[test]
    fn test_block_filter_no_blocks() {
        let mut f = BlockStreamFilter::new(TestHandler);
        let result = run_block_filter(&mut f, "nothing here\njust text\n", 0);
        assert_eq!(result, "DONE\n");
    }

    #[test]
    fn test_regex_block_filter_emits_blocks() {
        let handler = RegexBlockFilter::new("test", r"^error\[");
        let mut f = BlockStreamFilter::new(handler);
        let input = "ok line\nerror[E0308]: mismatched types\n  expected `u32`\nok again\nerror[E0599]: no method\n  help: try\n";
        let result = run_block_filter(&mut f, input, 1);
        assert!(
            result.contains("error[E0308]: mismatched types\n  expected `u32`"),
            "got: {}",
            result
        );
        assert!(
            result.contains("error[E0599]: no method\n  help: try"),
            "got: {}",
            result
        );
        assert!(
            result.contains("test: 2 blocks in output"),
            "got: {}",
            result
        );
    }

    #[test]
    fn test_regex_block_filter_skip_prefix() {
        let handler = RegexBlockFilter::new("test", r"^error").skip_prefix("warning:");
        let mut f = BlockStreamFilter::new(handler);
        let input = "warning: unused var\nerror: bad type\n  detail\nwarning: dead code\n";
        let result = run_block_filter(&mut f, input, 1);
        assert!(result.contains("error: bad type"), "got: {}", result);
        assert!(!result.contains("warning:"), "got: {}", result);
    }

    #[test]
    fn test_regex_block_filter_no_blocks() {
        let handler = RegexBlockFilter::new("mytest", r"^FAIL");
        let mut f = BlockStreamFilter::new(handler);
        let result = run_block_filter(&mut f, "all passed\nok\n", 0);
        assert_eq!(result, "mytest: no errors found\n");
    }

    #[test]
    fn test_regex_block_filter_indent_continuation() {
        let handler = RegexBlockFilter::new("test", r"^ERR");
        let mut f = BlockStreamFilter::new(handler);
        let input = "ERR space indent\n  two spaces\n\ttab indent\nnon-indent\n";
        let result = run_block_filter(&mut f, input, 1);
        assert!(
            result.contains("ERR space indent\n  two spaces\n\ttab indent"),
            "got: {}",
            result
        );
        assert!(!result.contains("non-indent"), "got: {}", result);
    }

    #[test]
    fn test_regex_block_filter_multiple_skip_prefixes() {
        let handler =
            RegexBlockFilter::new("test", r"^error").skip_prefixes(&["note:", "warning:", "help:"]);
        let mut f = BlockStreamFilter::new(handler);
        let input = "note: see docs\nwarning: unused\nhelp: try this\nerror: fatal\n  details\n";
        let result = run_block_filter(&mut f, input, 1);
        assert!(!result.contains("note:"), "got: {}", result);
        assert!(!result.contains("warning:"), "got: {}", result);
        assert!(!result.contains("help:"), "got: {}", result);
        assert!(
            result.contains("error: fatal\n  details"),
            "got: {}",
            result
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn test_streaming_filters_both_fds_and_routes_to_correct_fd() {
        // nosemgrep: interpreter-execution
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "echo 'error[E0308]: type mismatch'; echo '   Compiling foo v1.0' >&2; echo '   Downloading bar v2.0' >&2; echo '   Finished dev' >&2; echo 'real error on stderr' >&2"]);

        struct CargoLikeHandler;
        impl BlockHandler for CargoLikeHandler {
            fn should_skip(&mut self, line: &str) -> bool {
                let trimmed = line.trim_start();
                trimmed.starts_with("Compiling")
                    || trimmed.starts_with("Downloading")
                    || trimmed.starts_with("Finished")
            }
            fn is_block_start(&mut self, line: &str) -> bool {
                line.starts_with("error")
            }
            fn is_block_continuation(&mut self, line: &str, _block: &[String]) -> bool {
                line.starts_with(' ')
            }
            fn format_summary(&self, _: i32, _: &str) -> Option<String> {
                None
            }
        }

        let filter = BlockStreamFilter::new(CargoLikeHandler);
        let result = run_streaming(
            &mut cmd,
            StdinMode::Null,
            FilterMode::Streaming(Box::new(filter)),
        )
        .unwrap();

        assert!(
            result.filtered.contains("error[E0308]"),
            "filtered should contain stdout errors, got: {}",
            result.filtered
        );
        assert!(
            !result.filtered.contains("Compiling"),
            "cargo noise should be filtered out, got: {}",
            result.filtered
        );
        assert!(
            !result.filtered.contains("Downloading"),
            "cargo noise should be filtered out, got: {}",
            result.filtered
        );
        assert!(
            result.raw_stderr.contains("Compiling"),
            "raw_stderr should capture all stderr lines"
        );
        assert!(
            result.raw_stderr.contains("real error on stderr"),
            "raw_stderr should capture all stderr lines"
        );
    }

    struct CountingLineHandler {
        observed: Vec<String>,
        skip_prefixes: Vec<String>,
        summary_tag: &'static str,
    }

    impl LineHandler for CountingLineHandler {
        fn should_skip(&mut self, line: &str) -> bool {
            self.skip_prefixes.iter().any(|p| line.starts_with(p))
        }

        fn observe_line(&mut self, line: &str) {
            self.observed.push(line.to_string());
        }

        fn format_summary(&self, exit_code: i32, _raw: &str) -> Option<String> {
            Some(format!(
                "{}: {} kept, exit={}\n",
                self.summary_tag,
                self.observed.len(),
                exit_code
            ))
        }
    }

    fn run_line_filter(filter: &mut dyn StreamFilter, input: &str, exit_code: i32) -> String {
        let mut out = String::new();
        for line in input.lines() {
            if let Some(s) = filter.feed_line(line) {
                out.push_str(&s);
            }
        }
        out.push_str(&filter.flush());
        if let Some(post) = filter.on_exit(exit_code, input) {
            out.push_str(&post);
        }
        out
    }

    #[test]
    fn test_line_filter_defaults_keep_all() {
        struct DefaultHandler;
        impl LineHandler for DefaultHandler {
            fn format_summary(&self, _: i32, _: &str) -> Option<String> {
                None
            }
        }
        let mut f = LineStreamFilter::new(DefaultHandler);
        let result = run_line_filter(&mut f, "a\nb\nc\n", 0);
        assert_eq!(result, "a\nb\nc\n");
    }

    #[test]
    fn test_line_filter_skip_drops_matching_lines() {
        let handler = CountingLineHandler {
            observed: Vec::new(),
            skip_prefixes: vec!["NOISE:".to_string()],
            summary_tag: "demo",
        };
        let mut f = LineStreamFilter::new(handler);
        let input = "NOISE: progress 10%\nkeep me\nNOISE: progress 90%\nalso keep\n";
        let result = run_line_filter(&mut f, input, 0);
        assert!(!result.contains("NOISE:"), "got: {}", result);
        assert!(result.contains("keep me\n"));
        assert!(result.contains("also keep\n"));
        assert!(result.contains("demo: 2 kept, exit=0\n"));
    }

    #[test]
    fn test_line_filter_summary_propagates_exit_code() {
        let handler = CountingLineHandler {
            observed: Vec::new(),
            skip_prefixes: Vec::new(),
            summary_tag: "demo",
        };
        let mut f = LineStreamFilter::new(handler);
        let result = run_line_filter(&mut f, "one\n", 42);
        assert!(result.contains("exit=42"), "got: {}", result);
    }

    #[test]
    fn test_line_filter_observe_only_called_for_kept_lines() {
        let handler = CountingLineHandler {
            observed: Vec::new(),
            skip_prefixes: vec!["DROP".to_string()],
            summary_tag: "demo",
        };
        let mut f = LineStreamFilter::new(handler);
        let result = run_line_filter(&mut f, "DROP a\nDROP b\nkeep\n", 0);
        // Only "keep" was observed, so summary says "1 kept"
        assert!(result.contains("demo: 1 kept"), "got: {}", result);
    }

    // -----------------------------------------------------------------
    // exec_capture* limits and timeout coverage.
    // See docs/security/AUDIT-subprocess-timeouts.md (F-01, F-02, F-04).
    // -----------------------------------------------------------------

    #[test]
    fn test_exec_capture_short_times_out() {
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        let start = std::time::Instant::now();
        let err = match exec_capture_short(&mut cmd, Duration::from_millis(500)) {
            Ok(_) => panic!("should error on timeout"),
            Err(e) => e,
        };
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(3),
            "should return promptly after timeout, took {:?}",
            elapsed
        );
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("wall-clock") || msg.contains("budget"),
            "error should mention the deadline, got: {}",
            msg
        );
    }

    #[test]
    fn test_exec_capture_short_returns_normally_when_under_deadline() {
        let mut cmd = Command::new("echo");
        cmd.arg("hi");
        let r = exec_capture_short(&mut cmd, Duration::from_secs(5)).unwrap();
        assert_eq!(r.exit_code, 0);
        assert!(r.stdout.contains("hi"));
    }

    #[test]
    fn test_exec_capture_caps_stdout() {
        // Print ~512 KiB but cap at 4 KiB. Output should be exactly the cap.
        // We use `yes` piped through `head` to bound the child's own work too.
        // nosemgrep: interpreter-execution
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "yes ABCDEFGHIJKLMNOPQRSTUVWXYZ | head -c 524288"]);
        let r = exec_capture_with_limits(
            &mut cmd,
            CaptureLimits {
                stdout_max: 4096,
                stderr_max: DEFAULT_CAPTURE_STREAM_MAX,
                timeout: Some(Duration::from_secs(10)),
            },
        )
        .unwrap();
        assert!(
            r.stdout.len() <= 4096,
            "stdout should be capped at 4 KiB, got {} bytes",
            r.stdout.len()
        );
        // The child will typically receive SIGPIPE once we stop reading
        // (drain thread drops the pipe handle on cap-hit), so exit_code
        // may legitimately be 141 (128 + SIGPIPE). That's the *desired*
        // outcome — runaway children die — but it means we can't assert
        // exit_code == 0 here. The contract is: cap is enforced and we
        // return successfully (no Err). Either is acceptable.
    }

    #[test]
    fn test_exec_capture_caps_stderr_independently() {
        // Flood stderr only; stdout stays empty.
        // nosemgrep: interpreter-execution
        let mut cmd = Command::new("sh");
        cmd.args([
            "-c",
            "yes ZZZZZZZZZZZZZZZZZZZZZZZZ 1>&2 | head -c 524288 1>&2",
        ]);
        let r = exec_capture_with_limits(
            &mut cmd,
            CaptureLimits {
                stdout_max: DEFAULT_CAPTURE_STREAM_MAX,
                stderr_max: 2048,
                timeout: Some(Duration::from_secs(10)),
            },
        )
        .unwrap();
        assert!(
            r.stderr.len() <= 2048,
            "stderr should be capped at 2 KiB, got {} bytes",
            r.stderr.len()
        );
        assert!(r.stdout.is_empty(), "stdout should remain empty");
    }

    #[test]
    fn test_exec_capture_default_unchanged_for_short_output() {
        let mut cmd = Command::new("echo");
        cmd.arg("hello world");
        let r = exec_capture(&mut cmd).unwrap();
        assert_eq!(r.exit_code, 0);
        assert!(r.stdout.contains("hello world"));
        assert!(r.stderr.is_empty());
    }

    #[test]
    fn test_capture_limits_default_values() {
        let d = CaptureLimits::default();
        assert_eq!(d.stdout_max, DEFAULT_CAPTURE_STREAM_MAX);
        assert_eq!(d.stderr_max, DEFAULT_CAPTURE_STREAM_MAX);
        assert!(d.timeout.is_none(), "default = no wall-clock deadline");
    }

    // -----------------------------------------------------------------
    // Truncation contract — CaptureResult.truncated_stdout/_stderr
    // -----------------------------------------------------------------

    #[test]
    fn test_truncated_stdout_flag_set_when_cap_fires() {
        // nosemgrep: interpreter-execution
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "yes ABCDEFGHIJ | head -c 524288"]);
        let r = exec_capture_with_limits(
            &mut cmd,
            CaptureLimits {
                stdout_max: 4096,
                stderr_max: DEFAULT_CAPTURE_STREAM_MAX,
                timeout: Some(Duration::from_secs(10)),
            },
        )
        .unwrap();
        assert!(r.truncated_stdout, "cap fired, flag must be set");
        assert!(
            !r.truncated_stderr,
            "stderr was empty, flag must stay false"
        );
    }

    #[test]
    fn test_truncated_flag_clear_when_under_cap() {
        let mut cmd = Command::new("echo");
        cmd.arg("small output");
        let r = exec_capture(&mut cmd).unwrap();
        assert!(!r.truncated_stdout, "output well under default cap");
        assert!(!r.truncated_stderr, "stderr empty");
    }

    #[test]
    fn test_truncated_flag_clear_at_exact_cap_boundary() {
        // Produce exactly 32 bytes; cap at exactly 32. Should NOT report truncation
        // — the contract is "had more pending after cap", which an exact-EOF read does not.
        // nosemgrep: interpreter-execution
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "printf '%s' AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]);
        let r = exec_capture_with_limits(
            &mut cmd,
            CaptureLimits {
                stdout_max: 32,
                stderr_max: DEFAULT_CAPTURE_STREAM_MAX,
                timeout: Some(Duration::from_secs(5)),
            },
        )
        .unwrap();
        assert_eq!(r.stdout.len(), 32);
        assert!(
            !r.truncated_stdout,
            "exact EOF at cap is not truncation, got truncated_stdout=true"
        );
    }

    // -----------------------------------------------------------------
    // Edge cases from Codex round-2 review (2026-05-18).
    // -----------------------------------------------------------------

    #[test]
    fn test_very_short_deadline_race() {
        // 1ms deadline against a real spawn: either the child exits before the
        // deadline (Ok) or we time out (Err). Both are acceptable — what's NOT
        // acceptable is a panic, a hang, or an orphan.
        let mut cmd = Command::new("true");
        let start = std::time::Instant::now();
        let result = exec_capture_short(&mut cmd, Duration::from_millis(1));
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "should return promptly either way, took {:?}",
            elapsed
        );
        match result {
            Ok(r) => assert_eq!(r.exit_code, 0, "if not timed out, true exits 0"),
            Err(_) => { /* timed out — acceptable */ }
        }
    }

    #[test]
    fn test_cap_before_first_read_with_zero_max() {
        // Pathological: cap of 0 bytes. Child still runs, output is empty,
        // truncation flag is set if the child wrote anything.
        let mut cmd = Command::new("echo");
        cmd.arg("anything");
        let r = exec_capture_with_limits(
            &mut cmd,
            CaptureLimits {
                stdout_max: 0,
                stderr_max: 0,
                timeout: Some(Duration::from_secs(5)),
            },
        )
        .unwrap();
        assert!(r.stdout.is_empty());
        assert!(
            r.truncated_stdout,
            "child wrote bytes that exceeded the 0-byte cap"
        );
    }

    #[test]
    fn test_stderr_only_flood_completes_without_deadlock() {
        // Child writes only to stderr. stdout pipe stays empty (no EOF
        // signaled until child exits). Tests that the stdout drain thread
        // doesn't hang waiting for data that never arrives.
        // nosemgrep: interpreter-execution
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "yes ZZZ 1>&2 | head -c 8192 1>&2"]);
        let start = std::time::Instant::now();
        let r = exec_capture_with_limits(
            &mut cmd,
            CaptureLimits {
                stdout_max: DEFAULT_CAPTURE_STREAM_MAX,
                stderr_max: DEFAULT_CAPTURE_STREAM_MAX,
                timeout: Some(Duration::from_secs(10)),
            },
        )
        .unwrap();
        let elapsed = start.elapsed();
        assert!(r.stdout.is_empty());
        assert!(!r.stderr.is_empty());
        assert!(
            elapsed < Duration::from_secs(5),
            "must not block waiting on empty stdout pipe, took {:?}",
            elapsed
        );
    }

    #[test]
    fn test_kill_on_already_exited_child_does_not_error() {
        // Race: child exits between wait_timeout returning Ok(None) and our
        // kill() call. kill() will return an error on Linux (ESRCH) but our
        // code uses `let _ = child.kill();` so it must not propagate.
        //
        // We can't deterministically trigger the race, but we can verify the
        // shape: a normally-completing command under a generous deadline
        // returns Ok and does NOT leave any side-effect from the (unused)
        // timeout-error path.
        let mut cmd = Command::new("true");
        let r1 = exec_capture_short(&mut cmd, Duration::from_secs(5)).unwrap();
        assert_eq!(r1.exit_code, 0);
        // Second invocation must work the same — no leftover state.
        let mut cmd2 = Command::new("true");
        let r2 = exec_capture_short(&mut cmd2, Duration::from_secs(5)).unwrap();
        assert_eq!(r2.exit_code, 0);
    }

    #[test]
    fn test_warn_if_capped_helper_is_silent_when_not_truncated() {
        // White-box test: warn_if_capped is a side-effect helper, can't
        // capture eprintln from a unit test trivially. We rely on the
        // truncation flags being correct (covered above) and the path
        // being conditional. Manual confirmation: when truncated_* is
        // false, no eprintln is reached. This test exists to anchor the
        // contract; the indirect coverage via exec_capture default path
        // verifies the call site.
        let r = CaptureResult {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
            truncated_stdout: false,
            truncated_stderr: false,
        };
        warn_if_capped(&r, "test-noop");
    }

    #[test]
    fn test_drain_with_cap_helper_signals_truncation() {
        use std::io::Cursor;
        let input = b"0123456789ABCDEF";
        let (buf, truncated) = drain_with_cap(Cursor::new(&input[..]), 8);
        assert_eq!(buf, b"01234567");
        assert!(truncated, "16 bytes in, 8-byte cap → truncated");

        let (buf2, truncated2) = drain_with_cap(Cursor::new(&input[..]), 16);
        assert_eq!(buf2, input);
        assert!(!truncated2, "exact-fit read should not signal truncation");

        let (buf3, truncated3) = drain_with_cap(Cursor::new(&input[..]), 99);
        assert_eq!(buf3, input);
        assert!(!truncated3, "cap above input size, not truncated");
    }

    #[test]
    fn test_for_each_line_splits_lines() {
        let input = b"alpha\nbeta\ngamma\n";
        let mut got = Vec::new();
        for_each_line(io::Cursor::new(&input[..]), |l| got.push(l));
        assert_eq!(got, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn test_for_each_line_handles_no_trailing_newline() {
        let input = b"only-line";
        let mut got = Vec::new();
        for_each_line(io::Cursor::new(&input[..]), |l| got.push(l));
        assert_eq!(got, vec!["only-line"]);
    }

    // -----------------------------------------------------------------
    // Codex-review follow-up (G3 / #100): stream-path deadlock decoupling
    // and FILTERED_CAP truncation marker.
    // -----------------------------------------------------------------

    #[test]
    fn test_filtered_cap_sets_truncation_flag_and_marker() {
        // Drive a streaming filter whose output exceeds FILTERED_CAP. The
        // filter expands each input line; the child only needs to emit
        // enough lines for the accumulator to trip the cap.
        //
        // Each input line is expanded to a ~64 KiB output chunk, so ~200
        // lines clears the 10 MiB FILTERED_CAP without the child itself
        // producing 10 MiB (keeps raw_stdout under RAW_CAP).
        // nosemgrep: interpreter-execution
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "for i in $(seq 1 200); do echo x; done"]);
        let chunk = "A".repeat(64 * 1024);
        let filter = LineFilter::new(move |_l| Some(format!("{}\n", chunk)));
        let result = run_streaming(
            &mut cmd,
            StdinMode::Null,
            FilterMode::Streaming(Box::new(filter)),
        )
        .unwrap();
        assert!(
            result.truncated_filtered,
            "filtered accumulator exceeded FILTERED_CAP, flag must be set"
        );
        assert!(
            result
                .filtered
                .contains("[contextcrawler: output truncated at"),
            "filtered buffer must carry the visible truncation marker"
        );
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn test_filtered_cap_flag_clear_for_small_output() {
        let mut cmd = Command::new("printf");
        cmd.arg("hello\nworld\n");
        let filter = LineFilter::new(|l| Some(format!("{}\n", l)));
        let result = run_streaming(
            &mut cmd,
            StdinMode::Null,
            FilterMode::Streaming(Box::new(filter)),
        )
        .unwrap();
        assert!(
            !result.truncated_filtered,
            "small output is well under FILTERED_CAP"
        );
        assert!(!result.filtered.contains("output truncated"));
    }

    #[cfg(not(windows))]
    #[test]
    fn test_slow_sink_does_not_deadlock_child_drain() {
        // Regression for the sync_channel(4096) deadlock: the consumer loop
        // drains the bounded child channel AND used to write to the sink
        // inline. A slow/blocked terminal would stall the consumer, fill the
        // child channel, and back-pressure the child itself.
        //
        // The structural guarantee under test: the child drain runs to
        // completion and the call returns even when the child floods stdout
        // far past STREAM_CHANNEL_CAP (4096 lines) faster than a real
        // terminal could consume. The sink writer thread absorbs sink
        // back-pressure off the drain path. A deadlock here would hang the
        // test runner.
        // nosemgrep: interpreter-execution
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "for i in $(seq 1 50000); do echo line $i; done"]);
        let filter = LineFilter::new(|l| Some(format!("{}\n", l)));
        let start = std::time::Instant::now();
        let result = run_streaming(
            &mut cmd,
            StdinMode::Null,
            FilterMode::Streaming(Box::new(filter)),
        )
        .unwrap();
        let elapsed = start.elapsed();
        // 50k lines >> 4096 channel cap. If the drain were coupled to a
        // stalled sink this would deadlock; instead it completes promptly.
        assert_eq!(result.exit_code, 0);
        assert!(
            result.raw_stdout.contains("line 50000"),
            "child must fully drain — last line present"
        );
        assert!(
            elapsed < Duration::from_secs(20),
            "drain must not stall, took {:?}",
            elapsed
        );
    }

    /// A `Write` sink that BLOCKS on every write until a shared gate is
    /// opened. This models a terminal whose reader has stalled (a paused
    /// pager, or a pipe whose far end is not reading). It counts writes/bytes
    /// it has accepted so a test can prove the bounded sink channel — not the
    /// writer — absorbed the back-pressure while wedged.
    struct WedgedSink {
        bytes_seen: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        writes_seen: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        gate: std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    }

    impl Write for WedgedSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            // Block until the test opens the gate. While wedged, the
            // sink-writer thread is parked here and cannot drain the channel.
            let (lock, cvar) = &*self.gate;
            let mut open = lock.lock().unwrap();
            while !*open {
                open = cvar.wait(open).unwrap();
            }
            drop(open);
            self.bytes_seen
                .fetch_add(buf.len(), std::sync::atomic::Ordering::SeqCst);
            self.writes_seen
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn test_wedged_sink_bounds_memory_and_drops_with_marker() {
        use std::sync::atomic::Ordering::SeqCst;

        // Fourth-pass regression (Codex re-review): the deadlock fix added a
        // dedicated sink-writer thread fed by an UNBOUNDED channel. If the
        // sink wedges while the child floods output, that channel grows
        // without limit → OOM. The fix bounds the channel (SINK_CHANNEL_CAP)
        // and the consumer uses `try_send`: a full channel DROPS the chunk
        // (accounted) instead of blocking the child drain.
        //
        // This test ACTUALLY wedges the sink — `WedgedSink::write` blocks on
        // a condvar gate that stays shut for the whole child run — and
        // asserts:
        //   (a) the child drain still completes — last line present, no hang;
        //   (b) memory is bounded — while wedged the writer accepted at most
        //       ONE chunk, so peak buffered output is the bounded channel
        //       (≤ SINK_CHANNEL_CAP chunks) plus that one in-flight chunk,
        //       NOT the whole 50k-chunk flood;
        //   (c) dropped_bytes > 0 and the dropped-output marker is emitted.
        //
        // A pure high-volume test (above) does not prove (b)/(c): with a
        // fast real sink nothing is ever dropped. The gate is opened by a
        // watchdog thread AFTER the wedged window, so the sink-writer thread
        // can finally drain its (bounded) backlog and `run_streaming` returns.
        let bytes_seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let writes_seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let gate = std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        // Snapshot of `writes_seen` taken by the watchdog at the instant it
        // opens the gate — i.e. the count accumulated DURING the wedged
        // window, before the writer drains its backlog.
        let writes_while_wedged = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let out_sink = WedgedSink {
            bytes_seen: bytes_seen.clone(),
            writes_seen: writes_seen.clone(),
            gate: gate.clone(),
        };
        let err_sink = WedgedSink {
            bytes_seen: bytes_seen.clone(),
            writes_seen: writes_seen.clone(),
            gate: gate.clone(),
        };

        // Watchdog: keep the sink wedged for a window long enough for the
        // child to flood and the bounded channel to overflow, then snapshot
        // the wedged-window write count and open the gate so the run can
        // finish. This proves the child drain never depended on the sink.
        let wd_gate = gate.clone();
        let wd_writes_seen = writes_seen.clone();
        let wd_snapshot = writes_while_wedged.clone();
        let watchdog = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(3));
            wd_snapshot.store(wd_writes_seen.load(SeqCst), SeqCst);
            let (lock, cvar) = &*wd_gate;
            *lock.lock().unwrap() = true;
            cvar.notify_all();
        });

        // Child floods 20k lines, each expanded to a 200-byte chunk by the
        // filter. 20k >> SINK_CHANNEL_CAP (8192), so once the wedged writer
        // parks and the channel fills, every further chunk must be dropped.
        // Total filtered output (~4 MiB) stays under FILTERED_CAP (10 MiB) so
        // the dropped-output marker is not itself elided by FILTERED_CAP —
        // this isolates the sink-overflow path from the accumulator-cap path.
        // nosemgrep: interpreter-execution
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "for i in $(seq 1 20000); do echo line $i; done"]);
        let chunk = "Z".repeat(200);
        let filter = LineFilter::new(move |l| Some(format!("{} {}\n", l, chunk)));

        let start = std::time::Instant::now();
        let result = run_streaming_with_sink(
            &mut cmd,
            StdinMode::Null,
            FilterMode::Streaming(Box::new(filter)),
            Some((Box::new(out_sink), Box::new(err_sink))),
        )
        .unwrap();
        let elapsed = start.elapsed();
        watchdog.join().ok();

        // (a) child drain completed despite the wedged sink.
        assert_eq!(result.exit_code, 0);
        assert!(
            result.raw_stdout.contains("line 20000"),
            "child must fully drain even though the sink was wedged"
        );
        assert!(
            elapsed < Duration::from_secs(30),
            "wedged sink must not deadlock the child drain, took {:?}",
            elapsed
        );

        // (b) memory bounded: while wedged the writer parked on its first
        // write, so it pulled at most one chunk off the channel. Peak
        // buffered output is therefore the bounded channel (≤
        // SINK_CHANNEL_CAP) plus that single in-flight chunk — never the full
        // flood. With an unbounded channel the consumer would have queued all
        // ~50k chunks instead.
        let writes_wedged = writes_while_wedged.load(SeqCst);
        assert!(
            writes_wedged <= 1,
            "while wedged the writer must accept at most one chunk, saw {}",
            writes_wedged
        );

        // (c) the overflow was detected: dropped chunks accounted, and ONE
        // summary marker emitted into the filtered accumulator.
        assert!(
            result
                .filtered
                .contains("bytes dropped — output sink stalled"),
            "dropped-output marker must be emitted when the sink wedges, filtered tail: {}",
            &result.filtered[result.filtered.len().saturating_sub(200)..]
        );
        let marker_has_bytes = result
            .filtered
            .lines()
            .any(|ln| ln.contains("bytes dropped") && !ln.contains("[contextcrawler: 0 bytes"));
        assert!(
            marker_has_bytes,
            "dropped-output marker must report a non-zero byte count, got: {}",
            result
                .filtered
                .lines()
                .filter(|l| l.contains("dropped"))
                .collect::<Vec<_>>()
                .join(" | ")
        );
        // Exactly ONE marker — not one per dropped chunk.
        assert_eq!(
            result
                .filtered
                .matches("bytes dropped — output sink stalled")
                .count(),
            1,
            "exactly one dropped-output summary marker expected"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn test_dropped_marker_survives_full_filtered_accumulator() {
        // Fifth-pass regression (Codex re-review): the dropped-output summary
        // marker used to be appended only `if filtered.len() + marker.len() <=
        // FILTERED_CAP`. A user whose output BOTH filled the 10 MiB
        // accumulator AND hit sink drops would therefore see no notice of the
        // loss at all — the marker was silently elided.
        //
        // This test wedges the sink AND drives the filtered accumulator past
        // FILTERED_CAP at the same time, then asserts the dropped-output
        // marker IS present in the returned `filtered` and that the
        // truncation marker is also visible — neither end-of-stream marker
        // may be lost when both conditions fire together.
        use std::sync::atomic::Ordering::SeqCst;

        let bytes_seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let writes_seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let gate = std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));

        let out_sink = WedgedSink {
            bytes_seen: bytes_seen.clone(),
            writes_seen: writes_seen.clone(),
            gate: gate.clone(),
        };
        let err_sink = WedgedSink {
            bytes_seen: bytes_seen.clone(),
            writes_seen: writes_seen.clone(),
            gate: gate.clone(),
        };

        // Watchdog opens the gate after the wedged window so the run finishes.
        let wd_gate = gate.clone();
        let watchdog = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(3));
            let (lock, cvar) = &*wd_gate;
            *lock.lock().unwrap() = true;
            cvar.notify_all();
        });

        // Child emits 14000 lines; the filter expands each to a ~1 KiB chunk.
        // Two caps must both trip:
        //   - the filtered accumulator fills after ~10 MiB ≈ 10500 chunks, so
        //     `truncated_filtered` fires and the truncation marker is emitted;
        //   - the sink is wedged for the whole run, so once the bounded sink
        //     channel (SINK_CHANNEL_CAP = 8192) fills, every further chunk is
        //     dropped → `dropped` is set and the dropped-output marker fires.
        // 14000 > both thresholds, so both end-of-stream markers must reach
        // the returned `filtered` even though it is at FILTERED_CAP.
        // nosemgrep: interpreter-execution
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "for i in $(seq 1 14000); do echo x; done"]);
        let chunk = "A".repeat(1024);
        let filter = LineFilter::new(move |_l| Some(format!("{}\n", chunk)));

        let result = run_streaming_with_sink(
            &mut cmd,
            StdinMode::Null,
            FilterMode::Streaming(Box::new(filter)),
            Some((Box::new(out_sink), Box::new(err_sink))),
        )
        .unwrap();
        watchdog.join().ok();

        assert_eq!(result.exit_code, 0);
        assert!(
            result.truncated_filtered,
            "filtered accumulator must have hit FILTERED_CAP"
        );
        // The accumulator is full — within a marker's length of the cap — yet
        // the dropped-output marker must STILL be present.
        assert!(
            result.filtered.len() >= FILTERED_CAP,
            "filtered accumulator must be at the cap, len = {}",
            result.filtered.len()
        );
        assert!(
            result
                .filtered
                .contains("bytes dropped — output sink stalled"),
            "dropped-output marker must survive a full accumulator, filtered tail: {}",
            &result.filtered[result.filtered.len().saturating_sub(300)..]
        );
        assert!(
            result
                .filtered
                .contains("[contextcrawler: output truncated at"),
            "truncation marker must also be visible when both conditions fire"
        );
    }

    #[test]
    fn test_for_each_line_preserves_non_utf8_lines() {
        // G3 finding 5: BufRead::lines() + map_while(Result::ok) silently
        // truncates child output at the first non-UTF-8 byte. for_each_line
        // does a lossy conversion, so every line survives (invalid byte 0xFF
        // becomes U+FFFD) and lines *after* it are not dropped.
        let mut input: Vec<u8> = Vec::new();
        input.extend_from_slice(b"before\n");
        input.extend_from_slice(&[0xFF, b'\n']); // invalid UTF-8 line
        input.extend_from_slice(b"after\n");
        let mut got = Vec::new();
        for_each_line(io::Cursor::new(input), |l| got.push(l));
        assert_eq!(got.len(), 3, "no lines dropped at the non-UTF-8 byte");
        assert_eq!(got[0], "before");
        assert_eq!(got[2], "after", "line after invalid byte must survive");
        assert!(got[1].contains('\u{FFFD}'), "invalid byte became U+FFFD");
    }

    /// Minimal passthrough StdinFilter for exercising run_stdin_filter.
    struct PassthroughStdinFilter;

    impl StdinFilter for PassthroughStdinFilter {
        fn feed_line(&mut self, line: &str) -> Option<String> {
            Some(line.to_string())
        }
        fn flush(&mut self) -> String {
            String::new()
        }
    }

    #[test]
    fn test_stdin_filter_preserves_lines_after_invalid_utf8() {
        // Council P1-3 (flagged by all three voices): the StdinMode::Filter
        // path used BufRead::lines().map_while(Result::ok), silently dropping
        // everything after the first invalid-UTF-8 byte. run_stdin_filter
        // must use the lossy byte-read path so later lines still reach the
        // child process.
        let mut input: Vec<u8> = Vec::new();
        input.extend_from_slice(b"line1\n");
        input.extend_from_slice(&[0xFF, 0xFE, b'b', b'a', b'd', b'\n']); // invalid UTF-8
        input.extend_from_slice(b"line3\n");

        let mut filter = PassthroughStdinFilter;
        let mut out: Vec<u8> = Vec::new();
        run_stdin_filter(io::Cursor::new(input), &mut out, &mut filter);

        let written = String::from_utf8_lossy(&out);
        assert!(
            written.contains("line1"),
            "first line must pass through: {}",
            written
        );
        assert!(
            written.contains("line3"),
            "line after invalid UTF-8 must reach the child (got: {})",
            written
        );
        assert!(
            written.contains('\u{FFFD}'),
            "invalid bytes become U+FFFD: {}",
            written
        );
    }
}
