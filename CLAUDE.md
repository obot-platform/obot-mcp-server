# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A FastMCP server that provides tools for discovering, searching, and connecting to MCP servers in an Obot environment. It bridges between Claude/AI models and the Obot platform's MCP server ecosystem.

## Commands

```bash
# Install dependencies
uv sync

# Start the MCP server (requires OBOT_URL env var)
uv run python main.py

# Run unit tests
uv run pytest test_server.py -v

# Run a single test
uv run pytest test_server.py::TestClassName::test_method -v
```

## Architecture

- **`main.py`** - Entry point. Adds a `/healthz` health check route, then runs the FastMCP server on `0.0.0.0:8080` at path `/mcp` using streamable-http transport.
- **`obot_mcp/server.py`** - FastMCP server exposing 4 MCP tools (all prefixed `obot_`):
  - `obot_list_mcp_servers` - Lists available MCP servers with optional runtime filtering
  - `obot_list_connected_mcp_servers` - Lists connected/configured MCP servers for the current user
  - `obot_search_mcp_servers` - Search servers by keyword (name/description), results ranked by match priority (title > short description > description)
  - `obot_connect_to_mcp_server` - Full connection flow: resolves ID as catalog entry or multi-user server, elicits configuration from user if needed, handles OAuth via URL-mode elicitation with polling, creates/launches the server, returns a `connect_url`
- **`obot_mcp/client.py`** - `ObotClient` async HTTP client using `httpx.AsyncClient`. Auth is forwarded from the incoming request's `Authorization` header (via `fastmcp.server.dependencies.get_http_request`), not from env vars. The connected-server tool joins `/api/all-mcps/entries`, `/api/all-mcps/servers`, `/api/mcp-servers`, and `/api/mcp-server-instances`.
- **`obot_mcp/config.py`** - Reads `OBOT_URL` env var (default: `http://localhost:8080`)

### Two Server Types

The Obot API exposes two kinds of MCP servers:
- **Catalog entries** (`/api/all-mcps/entries`) - Templates that can be instantiated into user servers. May require configuration (env vars, headers, URLs) and/or OAuth.
- **Multi-user servers** (`/api/all-mcps/servers`) - Already-deployed shared servers. May need URL configuration or OAuth but not env var setup.

### Connection Flow (`obot_connect_to_mcp_server`)

This is the most complex tool. It tries catalog entry first, falls back to multi-user server:
1. Fetches the catalog entry by ID (falls back to multi-user server if not found)
2. For catalog entries: rejects composite runtime, checks OAuth admin prereqs, looks for existing user server
3. Extracts configuration requirements from manifest (env vars, remote headers, URL templates/hostname constraints)
4. If config needed: builds a dynamic Pydantic model via `_build_elicitation_model()` and uses `ctx.elicit()` to collect values
5. Creates/configures the user server, validates launch, handles OAuth if needed
6. Returns `connect_url` in format `{OBOT_URL}/mcp-connect/{server_id}`

For multi-user servers: checks configured status, handles OAuth, returns connect_url directly.

### OAuth Flow

OAuth uses MCP URL-mode elicitation (`ElicitRequestURLParams`) with Nanobot-specific `_meta` keys (`ai.nanobot.meta/oauth-url`, `ai.nanobot.meta/server-name`). After user accepts, polls `get_mcp_server_oauth_url()` until it returns empty (token stored).

## Environment Variables

- `OBOT_URL` - Obot API base URL (default: `http://localhost:8080`)

## Testing

Tests are in `test_server.py`. Uses `pytest-asyncio` with `unittest.mock`. The `@mcp.tool()` decorator wraps functions into `FunctionTool` objects - access the underlying async function via `.fn` for direct testing (see `obot_connect_to_mcp_server_tool.fn` pattern in tests). Tests mock `obot_client` methods with `patch.object` and `AsyncMock`.
