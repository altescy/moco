# moco - MCP Observation and Control Operator

[![CI](https://github.com/altescy/moco/actions/workflows/ci.yml/badge.svg)](https://github.com/altescy/moco/actions/workflows/ci.yml)
[![Latest Release](https://img.shields.io/github/v/release/altescy/moco)](https://github.com/altescy/moco/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

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
- Built-in audit logging (SQLite)

## Configuration

- Project config: `.moco/config.toml`

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

By default, audit logging is enabled and written to `.moco/audit.db`.

## Add server config from CLI

```bash
cargo run -- add everything -- npx -y @modelcontextprotocol/server-everything
```

This writes or updates the `[mcp.servers.<name>]` entry in `.moco/config.toml`.

## Homebrew (tap)

Install from tap:

```bash
brew tap altescy/moco
brew install moco
```

During development (install from main HEAD):

```bash
brew install --HEAD altescy/moco/moco
```

## Audit logs and reports

Show recent logs:

```bash
cargo run -- logs --limit 100
```

Show summary report:

```bash
cargo run -- report --top-tools 10
```

## Project status

- Currently near MVP stage
- APIs, config keys, and defaults may change
