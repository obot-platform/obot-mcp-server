# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A FastMCP server that provides tools for discovering, searching, and connecting to MCP servers in an Obot environment. It bridges between Claude/AI models and the Obot platform's MCP server ecosystem.

## Commands

```bash
# Install dependencies
uv sync

# Start the MCP server
uv run python main.py

# Run unit tests
uv run pytest test_server.py -v

# Run a single test
uv run pytest test_server.py::TestClassName::test_method -v

# Run integration tests
uv run python integration_test.py

# Inspect server configuration and registered tools
uv run python inspect_server.py
```

## Architecture

```
main.py                     # Entry point - imports and runs the FastMCP server
obot_mcp/
├── __init__.py             # Exports the mcp server instance
├── server.py               # FastMCP server with 3 MCP tools
├── client.py               # ObotClient - async HTTP client for Obot API
└── config.py               # Configuration from environment variables
```

### Key Components

- **Config** (`config.py`): Reads `OBOT_SERVER_URL` and `OBOT_TOKEN` from environment variables
- **ObotClient** (`client.py`): Async HTTP client using `httpx.AsyncClient` with Bearer token auth
- **MCP Server** (`server.py`): FastMCP server exposing 3 tools:
  - `list_mcp_servers` - Lists available MCP servers with optional runtime filtering
  - `search_mcp_servers` - Search servers by keyword (name/description)
  - `get_mcp_server_connection` - Get connection info for a specific server

### Data Flow

1. Claude/AI calls an MCP tool
2. Tool function calls `ObotClient` methods to query Obot API
3. API responses are normalized via `_extract_server_info()`
4. Filtered/searched results returned to caller

## Environment Variables

- `OBOT_SERVER_URL` - Obot API base URL (default: `http://localhost:8080`)
- `OBOT_TOKEN` - Bearer token for Obot API authentication

## Testing

Unit tests use `pytest-asyncio` with `unittest.mock` for mocking async HTTP calls. Tests are organized by function: `TestExtractServerInfo`, `TestFilterByRuntime`, `TestSearchItems`, `TestListMcpServers`, `TestSearchMcpServers`, `TestGetMcpServerConnection`.
