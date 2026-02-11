# Obot MCP Server


MCP server for Obot that provides tools for discovering, searching, and connecting to MCP servers.

## Quick Start

```bash
uv sync
OBOT_SERVER_URL=<url> OBOT_TOKEN=<token> uv run main.py
```

## Docker

Pre-built images are available from GitHub Container Registry:

```bash
docker pull ghcr.io/obot-platform/obot-mcp-server:latest
docker run -e OBOT_SERVER_URL=<url> -e OBOT_TOKEN=<token> ghcr.io/obot-platform/obot-mcp-server:latest
```

The server listens on port 8080 and path `/mcp`.
