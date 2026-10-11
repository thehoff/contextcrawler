# ContextCrawler (OMP)

LAW GEN-CTXCRL-001. ContextCrawler is mandatory for tooling work. The extension is the mechanism. Do not prefix a shell command yourself, and do not avoid the native tools.

A bash or shell command is rewritten before it runs: `git status` becomes `contextcrawler git status`. An explicit deny (exit 2) does not run. Exit 0 and exit 3 both run the rewritten command. Any other result leaves the original command.

Native `read`, semantic `find`, `grep`, and `glob` stay native. Do not re-run them as `contextcrawler grep`, `find`, or `read`. A `grep` or `glob` result of 400 characters or more is compacted after the tool returns. `read` and `find` are not.

Invoke directly: `contextcrawler gain`, `gain --history`, `gain --weak-filters`, `discover`, `security`, `security log`, and `--version`.

`contextcrawler proxy grep` and `contextcrawler proxy git` run the wrapper. A raw diagnostic is `CONTEXTCRAWLER_PROXY_RAW=1 contextcrawler proxy <cmd>`.

The Tirith gate still scans every rewrite. The filter is a token saver, not a security bypass.
