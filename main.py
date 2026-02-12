"""Entry point for the Obot MCP server."""

from starlette.responses import JSONResponse
from obot_mcp import mcp

# Add health check endpoint
@mcp.custom_route("/healthz", methods=["GET"])
async def health_check(request):
    """Health check endpoint."""
    return JSONResponse({"status": "ok"}, status_code=200)

if __name__ == "__main__":
    mcp.run(transport="streamable-http", host="0.0.0.0", port=8080, path="/mcp")
