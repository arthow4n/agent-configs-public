---
name: codex-cli-remote-control-project-registration
description: Register a local folder as a Codex CLI Remote Control project and make it discoverable when trust alone is insufficient.
---

# Remote Project Registration

Use this skill when a user wants a local repository or folder to appear in Codex Remote Control. It is specifically for the distinction between a trusted project path and a Remote Control project/folder entry.

## Safety and scope

- Resolve and use the folder's absolute path. Preserve the user's requested folder exactly; do not silently substitute its parent or a different worktree.
- Treat trust, project registration, and thread creation as separate changes. Do not grant trust unless the user requested it or clearly authorized it.
- Do not hand-edit `state_*.sqlite`, WAL files, or other live Codex databases. Use the app-server API so concurrent Codex processes and migrations remain safe.
- Do not restart or toggle Remote Control as part of registration. It can drop the user's active remote session. Ask first if a reconnect is needed.
- A bootstrap Codex turn consumes model resources and creates a saved conversation. Run one only when the user has authorized that step.

## Procedure

1. Inspect the target directory and resolve its absolute path. Confirm it exists and, when the request concerns a repository, that it is the intended Git worktree.

2. If trust is in scope, ensure the user-level Codex config contains an entry like:

   ```toml
   [projects."/absolute/path/to/repo"]
   trust_level = "trusted"
   ```

   Preserve unrelated config and avoid duplicate entries.

3. Find the running app-server Unix socket. The usual location is the active Codex home directory's `app-server-control/app-server-control.sock`. Prefer the running server's configured socket over guessing a path.

4. Connect using the app-server JSON-RPC transport. For a Unix socket, use the documented WebSocket handshake, then send `initialize`, followed by the `initialized` notification. Request `project/list` first to avoid duplicate registration.

5. If the exact root is absent, call `project/create` with a deterministic idempotency key:

   ```json
   {
     "method": "project/create",
     "id": 1,
     "params": {
       "idempotencyKey": "local-root:/absolute/path/to/repo",
       "name": "repo-name",
       "roots": [{"path": "/absolute/path/to/repo"}]
     }
   }
   ```

   Save the returned `project.id`. If the server rejects the method or reports an unsupported protocol version, stop and report that instead of writing the database directly.

6. If the user needs the folder to appear in the normal Remote Control conversation/folder list and the list still excludes it, inspect thread sources. A plain `codex exec` session has source `exec` and may be excluded from the default listing. With explicit user authorization, create a durable, read-only `thread/start` using the target `cwd` and returned `projectId`, then complete one harmless bootstrap turn such as:

   ```text
   Run only the shell command: echo Hello World. After it succeeds, stop immediately. Do not inspect files, run any other commands, or modify anything.
   ```

   Use `sandbox: "read-only"` and `approvalPolicy: "never"` for this bootstrap. Do not run a turn merely to satisfy registration if the user has not authorized the model call.

7. Verify both layers through the live server:

   - `project/list` contains the project and exact root.
   - Default `thread/list` contains a target-path thread if a bootstrap turn was authorized.
   - The trust config contains the intended `trusted` entry when trust was requested.

8. Tell the user whether the server state is correct. If the client still does not show it, recommend refreshing or reconnecting the Remote Control client; do not restart the daemon without explicit approval.

## Expected diagnosis

If `project/list` is empty but the user can see other folders, the visible folders may be derived from normal persisted threads rather than the project registry. Compare `thread/list` results by `cwd` and `source`. In particular, `exec`-source threads are not necessarily included in the default Remote Control listing, while `vscode` or app-server-created durable threads generally are.

The official [Codex App Server documentation](https://learn.chatgpt.com/docs/app-server) describes the JSON-RPC initialization and Unix/WebSocket transport. The [Remote Connections documentation](https://learn.chatgpt.com/docs/remote-connections) explains that Remote uses the connected host's projects, files, and environment.
