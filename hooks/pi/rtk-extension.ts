/**
 * ContextCrawler — Pi extension.
 *
 * Rewrites bash commands to use contextcrawler for token savings before
 * Pi spawns them. Thin delegate: all rewrite logic lives in
 * `contextcrawler rewrite` (src/discover/registry.rs in the
 * ContextCrawler repo), which is the single source of truth. To change
 * rewrite rules, edit the Rust registry — not this file.
 *
 * Requires contextcrawler on PATH (with the rewrite subcommand).
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { createBashTool } from "@earendil-works/pi-coding-agent";
import { spawnSync } from "node:child_process";

const BINARY = "contextcrawler";

function binaryAvailable(): boolean {
	const result = spawnSync(BINARY, ["--version"], { stdio: "ignore" });
	return result.status === 0;
}

function rewrite(command: string): string {
	// `contextcrawler rewrite` exits non-zero (3) when a permission/Ask verdict
	// or a defence-in-depth gate downgrades auto-allow to Ask, OR when no
	// ContextCrawler equivalent exists (1). The rewritten command is still
	// emitted on stdout in the Ask case (see exit-code contract in
	// src/hooks/rewrite_cmd.rs) — the harness must USE that stdout rather than
	// treat the non-zero exit as failure. Only a genuinely useless stdout
	// (empty or byte-identical to the original) falls back to the raw command.
	const result = spawnSync(BINARY, ["rewrite", command], {
		encoding: "utf8",
		stdio: ["ignore", "pipe", "ignore"],
	});
	const out = (result.stdout ?? "").trim();
	if (!out) {
		return command;
	}
	if (result.status === 0 || out !== command) {
		return out;
	}
	return command;
}

export default function (pi: ExtensionAPI) {
	if (!binaryAvailable()) {
		console.warn(
			"[contextcrawler] binary not found on PATH — Pi extension disabled",
		);
		return;
	}

	pi.registerTool(
		createBashTool(process.cwd(), {
			spawnHook: ({ command, cwd, env }) => ({
				command: rewrite(command),
				cwd,
				env,
			}),
		}),
	);
}
