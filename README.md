# Obot MCP Server

MCP server for Obot that provides tools for discovering, searching, and connecting to MCP servers.

## Tools

- **`obot_list_mcp_servers`** - List available MCP servers with optional runtime filtering
- **`obot_list_connected_mcp_servers`** - List connected/configured MCP servers for the current user
- **`obot_search_mcp_servers`** - Search servers by keyword (matches name and description)
- **`obot_connect_to_mcp_server`** - Connect to a server by ID, handling configuration, OAuth, and launch

## Quick Start

```bash
uv sync
OBOT_URL=<url> uv run python main.py
```

The server listens on port 8080 and path `/mcp` using streamable-http transport.

## Docker

Pre-built images are available from GitHub Container Registry:

```bash
docker pull ghcr.io/obot-platform/obot-mcp-server:latest
docker run -e OBOT_URL=<url> -p 8080:8080 ghcr.io/obot-platform/obot-mcp-server:latest
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OBOT_URL` | Obot API base URL | `http://localhost:8080` |

Authentication is forwarded from the incoming request's `Authorization` header to the Obot API.

## Testing

```bash
uv run pytest test_server.py -v
```
