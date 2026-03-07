# moco - MCP Observation and Control Operator

`moco` is a lightweight MCP hub/proxy that aggregates multiple MCP servers.

This repository is still in an early development stage, and behavior/configuration may change.

## Current capabilities

- Expose multiple downstream MCP servers as a single MCP server (`stdio` / `streamable-http`)
- Namespace tool names as `server::tool`
- Apply security checks on both pre-call and post-call paths
  - regex / keyword / prompt-injection rules
  - local PII and credential detection
  - detection on decoded strings (base64 / URL-encoded / JSON-escaped)
- Provide lazy-index meta tools
  - `hub::discover_tools`
  - `hub::get_tool_schema`
  - `hub::execute_indexed_tool`
- Optional audit logging (JSONL)

## Configuration

- Project config: `.moco.toml` (recommended)
- Backward-compatible fallback: `.mcps.toml` (legacy name, still supported for now)

Minimal example:

```toml
[mcp]
default_timeout_ms = 30000

[mcp.servers.everything]
transport = "stdio"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-everything"]

[security]
mode = "enforce"
presets = ["pii-basic", "credential-standard", "prompt-injection-basic"]
preset_level = "balanced"
```

## Run

```bash
cargo run -- serve
```

`moco serve` starts as a stdio MCP server.

## Add server config from CLI

```bash
cargo run -- add everything -- npx -y @modelcontextprotocol/server-everything
```

This writes or updates the `[mcp.servers.<name>]` entry in `.moco.toml` (or an existing project config if present).

## Audit logging (optional)

```bash
MCPS_AUDIT_LOG=.moco-audit.jsonl cargo run
```

Optional tuning:

- `MCPS_AUDIT_MAX_BYTES` (default: 10MB)
- `MCPS_AUDIT_MAX_FILES` (default: 3)

## Project status

- Currently near MVP stage
- APIs, config keys, and defaults may change
