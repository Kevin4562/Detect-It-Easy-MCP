# Detect-It-Easy MCP Server

MCP server for binary analysis using **direct** [`die-python`](https://github.com/elastic/die-python) bindings.
- Typed structured outputs for LLM tooling
- Evidence extraction

## Quick Install (Copy/Paste)

```toml
[mcp_servers.detect_it_easy]
command = "uvx"
args = [
  "--python", "3.12",
  "--from", "git+https://github.com/Kevin4562/Detect-It-Easy-MCP.git",
  "detect-it-easy-mcp"
]
startup_timeout_sec = 30
tool_timeout_sec = 180
```

This works with no manual setup: `uvx` downloads the project and installs dependencies automatically.

## Local Development

```bash
uv sync
uv run detect-it-easy-mcp
```

Run tests:

```bash
uv run pytest
```

## Tools

### 1) `die_get_capabilities`
Returns installed DIE versions, resolved database path, scan flags with bitmasks/defaults, and supported raw output formats.

### 2) `die_scan_file`
Scans one file path and returns:
- raw DIE output (`json` / `xml` / `csv` / `tsv` / `plaintext`)
- parsed JSON tree
- flattened normalized detection records
- type counts and errors

### 3) `die_scan_memory_base64`
Scans base64-encoded bytes through DIE memory bindings, same options/output as `die_scan_file`.

### 4) `die_scan_batch`
Scans multiple files from explicit paths and/or directory globbing. Returns success results plus explicit per-file failures.

### 5) `die_compare_files`
Scans two files and returns shared, left-only, and right-only normalized records plus summary counts.

### 6) `die_extract_evidence`
Extracts packed/protection-relevant evidence records for LLM-side reasoning.

Important: this tool intentionally does **not** return a final packed verdict.

### 7) `die_list_signatures`
Lists `.sg` database signatures with optional filters (`format_filter`, `category_filter`, `name_contains`, `limit`).

### 8) `die_search_signatures`
Searches signatures by path/name/category and optionally signature file content.

### 9) `die_signature_statistics`
Returns signature counts by format family and category prefix.

## Scan Flags

Supported booleans map directly to DIE bitmasks:

- `deep_scan` (`0x00000001`)
- `heuristic_scan` (`0x00000002`)
- `all_types_scan` (`0x00000004`)
- `recursive_scan` (`0x00000008`)
- `verbose` (`0x00000010`)
- `aggressive_scan` (`0x00000020`)
- `overlay_scan` (`0x00000040`)
- `resources_scan` (`0x00000080`)
- `archives_scan` (`0x00000100`)
- `use_cache` (`0x01000000`)
- `format_result` (`0x10000000`)

Output format flags:

- `json` (`0x00020000`)
- `xml` (`0x00010000`)
- `tsv` (`0x00040000`)
- `csv` (`0x00080000`)
- `plaintext` (no format bit)

## Local Codex Config Example

For this workspace path:

```toml
[mcp_servers.detect_it_easy]
command = "uvx"
args = [
  "--python", "3.12",
  "--from", "c:/Users/User/Documents/Bin Analysis/Detect-It-Easy-MCP",
  "detect-it-easy-mcp"
]
startup_timeout_sec = 30
tool_timeout_sec = 180
```
