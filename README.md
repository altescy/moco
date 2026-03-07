# moco - MCP Observation and Control Operator

[![CI](https://github.com/altescy/moco/actions/workflows/ci.yml/badge.svg)](https://github.com/altescy/moco/actions/workflows/ci.yml)
[![Latest Release](https://img.shields.io/github/v/release/altescy/moco)](https://github.com/altescy/moco/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`moco` is a lightweight MCP hub/proxy that aggregates multiple MCP servers and provides built-in security controls.

This repository is still in an early stage, and behavior/configuration may change.

## Docs

- [Documentation Index](docs/index.md)
- [Quick Start](docs/quick-start.md)
- [Security Configuration](docs/security.md)

## Features

- Expose multiple downstream MCP servers as a single MCP server (`stdio`)
- Connect to downstream MCP servers via `stdio` or `streamable-http`
- Namespace tool names as `server::tool`
- Apply security checks on both pre-call and post-call paths
  - rule-specific detector schema (`regex` / `keyword` / `builtin` / `high_risk_tool`)
  - local PII and credential detection
  - detection on decoded strings (base64 / URL-encoded / JSON-escaped)
- Provide lazy-index meta tools
  - `hub::discover_tools`
  - `hub::get_tool_schema`
  - `hub::execute_indexed_tool`
- Built-in audit logging (SQLite)

## Install

### Homebrew

Install with a fully qualified formula name:

```bash
brew install altescy/moco/moco
```

### Cargo

Install from GitHub:

```bash
cargo install --git https://github.com/altescy/moco moco
```

## Usage

Start `moco` as a stdio MCP server:

```bash
moco serve
```

By default, audit logging is enabled and written to `.moco/audit.db`.

Add a downstream MCP server configuration:

```bash
moco add everything -- npx -y @modelcontextprotocol/server-everything
```

This writes or updates `[mcp.servers.<name>]` in `.moco/config.toml`.

## MCP Client Setup

`moco` currently exposes itself as a stdio MCP server, so each client should be configured to run `moco serve`.

### Claude Code

Add `moco` from CLI:

```bash
claude mcp add --transport stdio moco -- moco serve
```

Equivalent project config (`.mcp.json`):

```json
{
  "mcpServers": {
    "moco": {
      "command": "moco",
      "args": ["serve"]
    }
  }
}
```

### Codex (CLI / IDE)

Add `moco` from CLI:

```bash
codex mcp add moco -- moco serve
```

Codex stores MCP settings in `~/.codex/config.toml` (or project-local `.codex/config.toml`).
Equivalent manual config:

```toml
[mcp_servers.moco]
command = "moco"
args = ["serve"]
```

### OpenCode

Add to `opencode.json` (project) or `~/.config/opencode/opencode.json` (global):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "moco": {
      "type": "local",
      "command": ["moco", "serve"],
      "enabled": true
    }
  }
}
```

## Configuration

Minimal recommended starting point (`.moco/config.toml`):

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

See [docs](docs/security.md) for security configuration details.
