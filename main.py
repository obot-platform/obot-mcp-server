"""Entry point for the Obot MCP server."""

from obot_mcp import mcp

if __name__ == "__main__":
    mcp.run(transport="streamable-http", host="0.0.0.0", port=7999, path="/mcp")
