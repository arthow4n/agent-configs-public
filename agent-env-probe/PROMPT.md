# Agent Environment Probe Prompt

## Phase 1 — read-only environment inventory

Run `./agent_env_probe.sh` without modifying the script. Do not add flags. Return the complete stdout verbatim. Do not inspect credentials, environment variables, user files, browser profiles, or other private data. If a command is unavailable or blocked, leave the reported result as unavailable/blocked rather than attempting to bypass the restriction.

## Phase 2 — opt-in package/runtime capability tests

Only run this phase when explicitly authorized to perform temporary package downloads, temporary filesystem writes, and package execution.

Run:

```bash
./agent_package_probe.sh --all-install-tests
```

Return the complete stdout verbatim. Do not modify either probe script. Do not use `sudo`, a system package manager, global installs, shell-profile edits, or persistent PATH changes. Do not inspect credentials, environment variables, user files, browser profiles, package-manager credentials, or other private data. If a registry, download, runtime, hash check, package installation, or execution is unavailable or blocked, report the probe result as returned; do not attempt to bypass the restriction.

The package probe intentionally uses only temporary directories and deletes them afterward. It currently tests:

- Python/PyPI: pinned `packaging==26.3`, wheel-only, no dependencies, SHA-256 verification, temporary import/execution.
- Node/npm: pinned `ms@2.1.3`, isolated temporary npm configuration/cache, lifecycle scripts disabled, SHA-512 integrity verification, temporary install and execution.
- Existing Deno: `npm:ms@2.1.3` resolution and execution through Deno's npm compatibility layer using a temporary Deno cache.
- Portable Deno: pinned official Deno `v2.9.6` binary ZIP, platform-specific SHA-256 verification, temporary extraction/execution, followed by the same npm compatibility test.
