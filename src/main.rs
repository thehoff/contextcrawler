//! Thin binary shim. All CLI logic lives in the library (`cli::run`), so the
//! binary dogfoods the exact code path downstream embedders depend on.
fn main() {
    std::process::exit(contextcrawler::run());
}
