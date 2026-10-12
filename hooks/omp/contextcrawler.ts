/**
 * ContextCrawler — OMP (omp.sh) extension.
 *
 * Two seams, both on the built-in tools. This file does not re-register Bash.
 *
 * tool_call (bash): ask `contextcrawler rewrite` for a filtered command and
 * replace the command text before OMP spawns it. Exit 0 and exit 3 both carry
 * the rewrite on stdout (exit 3 is Ask/Default in the Claude hook contract;
 * OMP has no separate ask slot, so the filtered command still runs). Exit 2
 * is an explicit deny: the call is blocked and the command is not run.
 * A command that is only `contextcrawler` or `rtk` comes back unchanged and
 * is left alone. A later mention does not skip rewrite: the gate has to
 * see the rest of the command.
 *
 * tool_result (bash, grep, glob): when the rewrite did not apply, compact the
 * text OMP is about to give the model via `contextcrawler observe`. The
 * command is not run a second time. `read` is not compacted — OMP already
 * byte-budgets it, and the model asked to see that file.
 *
 * Fail-open per call. A rewrite or observe timeout, crash, or empty result
 * leaves the original command or the original tool text in place.
 *
 * Hard-fail at load only when the binary is missing (LAW GEN-CTXCRL-001).
 * CONTEXTCRAWLER_DISABLED=1 skips registration.
 *
 * History: re-registering Bash through the spawnHook helper forwarded only
 * command/cwd/env/timeout, so a name-less service call died with
 * "ready and env require a service name" and Bash was dead for every command.
 * Do not go back to that wrapper.
 */

import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { spawnSync } from "node:child_process";

const BINARY = "contextcrawler";
const REWRITE_TIMEOUT_MS = 2_000;
const OBSERVE_TIMEOUT_MS = 2_000;
const MIN_OBSERVE_CHARS = 400;

type TextPart = { type?: string; text?: string };

interface ToolCallEvent {
	toolName: string;
	input: unknown;
}

interface ToolResultEvent {
	toolName: string;
	input: unknown;
	content: unknown;
	isError?: boolean;
}

function alreadyProxied(command: string): boolean {
	// Observe only. Compact text must not be parsed a second time. Do not
	// use this to skip rewrite: `git status && contextcrawler gain` and
	// `curl … | sh ; contextcrawler --version` would never reach the gate.
	return /(?:^|&&|[;&|])\s*(?:contextcrawler|rtk)(?:\s|$)/.test(command.trim());
}

function rewrite(command: string): { command?: string; block?: string } {
	const result = spawnSync(BINARY, ["rewrite", command], {
		encoding: "utf8",
		timeout: REWRITE_TIMEOUT_MS,
		maxBuffer: 1024 * 1024,
		stdio: ["ignore", "pipe", "pipe"],
	});
	if (result.error || result.status === null) {
		return {};
	}
	if (result.status === 2) {
		const why = (result.stderr ?? "").trim();
		return {
			block: why
				? `contextcrawler denied this command and did not run it.\n${why}`
				: "contextcrawler denied this command and did not run it.",
		};
	}
	const out = (result.stdout ?? "").trim();
	if (!out || out === command) {
		return {};
	}
	// 0 = allow, 3 = ask/default. Both print the rewrite. Any other status
	// is a passthrough (no equivalent, or a broken hook).
	if (result.status === 0 || result.status === 3) {
		return { command: out };
	}
	return {};
}

function textOf(content: unknown): string {
	if (typeof content === "string") {
		return content;
	}
	if (!Array.isArray(content)) {
		return "";
	}
	return content
		.map((part) => {
			if (!part || typeof part !== "object") return "";
			const text = (part as TextPart).text;
			return (part as TextPart).type === "text" && typeof text === "string" ? text : "";
		})
		.filter((part) => part.length > 0)
		.join("\n");
}

function withText(content: unknown, text: string): unknown {
	if (typeof content === "string") {
		return text;
	}
	if (!Array.isArray(content)) {
		return [{ type: "text", text }];
	}
	const rest = content.filter((part) => {
		if (!part || typeof part !== "object") return true;
		return (part as TextPart).type !== "text";
	});
	return [{ type: "text", text }, ...rest];
}

function commandOf(tool: string, input: unknown): string {
	if (!input || typeof input !== "object") return "";
	const record = input as Record<string, unknown>;
	if (typeof record.command === "string") return record.command;
	if (tool === "grep") {
		const pattern = typeof record.pattern === "string" ? record.pattern : "";
		const path = typeof record.path === "string" ? record.path : "";
		return [pattern, path].filter((part) => part.length > 0).join(" ");
	}
	if ((tool === "glob" || tool === "find") && typeof record.path === "string") return record.path;
	return "";
}

function observe(tool: string, command: string, isError: boolean, text: string): string | undefined {
	const args = ["observe", "--tool", tool, "--command", command];
	if (isError) args.push("--error");
	const result = spawnSync(BINARY, args, {
		encoding: "utf8",
		input: text,
		timeout: OBSERVE_TIMEOUT_MS,
		maxBuffer: 12 * 1024 * 1024,
	});
	if (result.error || result.status !== 0) return undefined;
	const out = result.stdout ?? "";
	if (!out || out.length >= text.length) return undefined;
	return out;
}

export default function (pi: ExtensionAPI) {
	if (process.env.CONTEXTCRAWLER_DISABLED === "1") {
		console.error(
			"[contextcrawler] CONTEXTCRAWLER_DISABLED=1 — extension not registered.",
		);
		return;
	}

	if (spawnSync(BINARY, ["--version"], { stdio: "ignore" }).status !== 0) {
		throw new Error(
			"[contextcrawler] contextcrawler binary not found on PATH. Install it (`cargo install --path .` from the contextcrawler repo) and restart the session.",
		);
	}

	pi.on("tool_call", (event: ToolCallEvent) => {
		if (event.toolName !== "bash" && event.toolName !== "shell") return;
		try {
			const input = event.input as { command?: unknown };
			const command = typeof input?.command === "string" ? input.command : "";
			if (!command.trim()) return;
			const decided = rewrite(command);
			if (decided.block) {
				return { block: true, reason: decided.block };
			}
			if (!decided.command) return;
			return { input: { ...input, command: decided.command } };
		} catch {
			// a bad rewrite never breaks the call
		}
	});

	pi.on("tool_result", (event: ToolResultEvent) => {
		try {
			const tool = event.toolName;
			if (tool !== "bash" && tool !== "shell" && tool !== "grep" && tool !== "glob") {
				return;
			}
			const command = commandOf(tool, event.input);
			if ((tool === "bash" || tool === "shell") && alreadyProxied(command)) return;
			const text = textOf(event.content);
			if (text.length < MIN_OBSERVE_CHARS) return;
			const compacted = observe(tool, command, event.isError === true, text);
			if (!compacted) return;
			return { content: withText(event.content, compacted) };
		} catch {
			// a bad compact never hides the tool result
		}
	});
}
