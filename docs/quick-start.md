# Quick Start

This guide gets `moco` running as an MCP hub/proxy in a few minutes.

## 1) Install

Choose one method.

Homebrew:

```bash
brew install altescy/moco/moco
```

Cargo:

```bash
cargo install --git https://github.com/altescy/moco moco
```

Verify:

```bash
moco --help
```

## 2) Add downstream MCP servers

Add a stdio MCP server:

```bash
moco add everything -- npx -y @modelcontextprotocol/server-everything
```

Add a streamable HTTP MCP server:

```bash
moco add --transport streamable-http sentry https://mcp.sentry.dev/mcp
```

This creates or updates `.moco/config.toml`.

## 3) Configure security presets

Minimal recommended starting point:

```toml
[security]
mode = "enforce"
presets = ["pii-basic", "credential-standard", "prompt-injection-basic"]
preset_level = "balanced"
```

For preset details, see [`security.md`](security.md).

## 4) Connect your MCP client

### Claude Code

```bash
claude mcp add --transport stdio moco -- moco serve
```

Then run `/mcp` inside Claude Code.

### Codex

```bash
codex mcp add moco -- moco serve
```

### OpenCode

Add to `opencode.json`:

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

## 5) Inspect audit logs and report

By default, `moco` exposes downstream tools in `tools/list` with their full `inputSchema`, so MCP clients can call namespaced tools directly (for example, `deepwiki::ask_question`) with structured arguments.

Check configured MCP servers and availability:

```bash
moco list
```

Recent events:

```bash
moco logs --limit 100
```

Summary report:

```bash
moco report --top-tools 10
```

## Manual run (optional)

In normal usage, your MCP client starts `moco serve` automatically.

Run it manually only for debugging:

```bash
moco serve
```
