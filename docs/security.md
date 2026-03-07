# Security Configuration

This document describes the security settings currently supported by `moco`.

## Security block

Configure security in `.moco/config.toml`:

```toml
[security]
mode = "enforce"
presets = ["pii-basic", "credential-standard", "prompt-injection-basic"]
preset_level = "balanced"
max_decode_depth = 4
max_decode_bytes = 262144
```

## Modes

- `off`: no security evaluation
- `monitor`: evaluate and log findings, but do not block or require confirmation
- `enforce`: apply detector actions (`allow` / `confirm` / `deny`)

## Presets (currently supported)

Supported preset names:

- `pii-basic`
- `credential-standard`
- `prompt-injection-basic`

`preset_level` values:

- `monitor`
- `balanced`
- `strict`

Preset behavior by level:

| Preset | monitor | balanced | strict |
| --- | --- | --- | --- |
| `pii-basic` | confirm | confirm | deny |
| `credential-standard` | confirm | deny | deny |
| `prompt-injection-basic` | confirm | confirm | deny |

Notes:

- In `mode = "monitor"`, final policy status is still `allow` even when detectors match.
- Presets expand to concrete detectors at load time.

## Decoding behavior

To catch obfuscated content, `moco` can inspect decoded variants of text.

- Unicode normalization: NFKC
- JSON escape decoding (for escaped strings)
- URL decoding
- Base64 decoding (standard and URL-safe variants)

Controls:

- `max_decode_depth` (default: `4`)
- `max_decode_bytes` (default: `262144`)

Each detector has `decode = true/false`.

- `true`: detector can inspect decoded variants
- `false`: detector checks only original text

## Custom detectors

You can define additional detectors under `security.detectors`.

Detector settings are rule-specific. Each detector has shared fields and a rule-specific payload.

Shared fields:

- `name`
- `type`
- `target`
- `action`
- `decode`

### Detector types

- `regex`: match `patterns` with Rust regex
- `keyword`: case-insensitive substring match using `keywords`
- `builtin`: use built-in `rule`
- `high_risk_tool`: glob match against tool names using `patterns`

Rule-specific required fields:

| type | Required fields |
| --- | --- |
| `regex` | `patterns` |
| `keyword` | `keywords` |
| `high_risk_tool` | `patterns` |
| `builtin` | `rule` |

### Targets

- `tool_name`: inspect tool name only
- `arguments`: inspect arguments/output text only
- `all`: inspect both

### Actions

- `allow`
- `confirm`
- `deny`

When multiple findings exist, the strongest action wins (`deny` > `confirm` > `allow`).

## Built-in rules

Built-in rule names currently available:

- `prompt_injection`
- `credential_entropy`
- `pii` (provider-backed)

Provider-backed rules use the local PII provider and detect email, phone, basic address, and credential-like strings.

### Built-in rule options

`rule = "prompt_injection"`

- No additional fields.

`rule = "credential_entropy"`

- Optional: `min_length` (default: `20`)
- Optional: `entropy_milli_threshold` (default: `3800`)

Example:

```toml
[[security.detectors]]
name = "entropy-credential"
type = "builtin"
rule = "credential_entropy"
target = "arguments"
action = "deny"
decode = true
min_length = 24
entropy_milli_threshold = 4000
```

### PII kind opt-out

For `rule = "pii"`, you can disable specific match kinds with `disabled`.

Available kinds:

- `email`
- `phone`
- `address`
- `credential`
- `other`

Example (detect PII except email):

```toml
[[security.detectors]]
name = "pii-no-email"
type = "builtin"
rule = "pii"
target = "arguments"
action = "confirm"
decode = true
disabled = ["email"]
```

## Tool overrides

Use `tool_overrides` for tool-name based policy overrides.

```toml
[security.tool_overrides."github::*"]
action = "confirm"
reason = "GitHub write tools require explicit confirmation"

[security.tool_overrides."shell::exec"]
action = "deny"
reason = "Direct shell execution is disallowed"
```

Override keys are glob patterns. If multiple patterns match, the strongest action wins.

## Full example

```toml
[security]
mode = "enforce"
presets = ["pii-basic", "credential-standard", "prompt-injection-basic"]
preset_level = "balanced"
max_decode_depth = 4
max_decode_bytes = 262144

[[security.detectors]]
name = "block-ssn"
type = "regex"
target = "arguments"
patterns = ["\\b\\d{3}-\\d{2}-\\d{4}\\b"]
action = "deny"
decode = true

[[security.detectors]]
name = "confirm-prod-keywords"
type = "keyword"
target = "all"
keywords = ["production", "drop table", "rm -rf"]
action = "confirm"
decode = false

[[security.detectors]]
name = "deny-high-risk-tools"
type = "high_risk_tool"
target = "tool_name"
patterns = ["shell::*", "admin::*"]
action = "deny"
decode = false

[[security.detectors]]
name = "deny-entropy-credentials"
type = "builtin"
rule = "credential_entropy"
target = "arguments"
action = "deny"
decode = true
min_length = 24
entropy_milli_threshold = 4000

[security.tool_overrides."admin::*"]
action = "deny"
reason = "Admin tools are blocked"
```
