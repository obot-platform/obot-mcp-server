"""FastMCP server with tools for Obot MCP server discovery and connection."""

from typing import Any, Dict, List, Literal, Optional

from fastmcp import FastMCP

from .client import ObotClient
from .config import config

# Create the FastMCP server
mcp = FastMCP("obot-mcp-server")

# Create a shared client instance
obot_client = ObotClient()


def _requires_url_configuration(manifest: Dict[str, Any]) -> bool:
    """
    Check if a remote server requires URL configuration from the user.

    Remote servers need URL configuration when they have a hostname constraint
    or URL template, but no fixed URL.

    Args:
        manifest: The server manifest

    Returns:
        True if URL configuration is required
    """
    if manifest.get("runtime") != "remote":
        return False

    remote_config = manifest.get("remoteConfig", {})
    if not remote_config:
        return False

    # If there's a fixed URL, no user configuration is needed
    if remote_config.get("fixedURL"):
        return False

    # If there's a hostname constraint or URL template, user must provide URL
    return bool(remote_config.get("hostname") or remote_config.get("urlTemplate"))


def _has_required_headers(manifest: Dict[str, Any]) -> bool:
    """
    Check if a remote server has required headers that need user input.

    Headers with a static value are pre-filled and don't need user input.
    Headers without a value that are marked required need user input.

    Args:
        manifest: The server manifest

    Returns:
        True if there are required headers needing user input
    """
    if manifest.get("runtime") != "remote":
        return False

    remote_config = manifest.get("remoteConfig", {})
    if not remote_config:
        return False

    headers = remote_config.get("headers", [])
    for header in headers:
        # If header has a static value, it doesn't need user input
        if header.get("value"):
            continue
        # If header is required and has no value, user must provide it
        if header.get("required", False):
            return True

    return False


def _extract_server_info(item: Dict[str, Any], item_type: str) -> Dict[str, Any]:
    """
    Extract common server information from API response.

    Args:
        item: Raw API response item
        item_type: Either "catalog_entry" or "multi_user_server"

    Returns:
        Dictionary with standardized server information
    """
    manifest = item.get("manifest", {})

    # ID is at the top level of the item (from embedded Metadata struct),
    # not nested inside a "metadata" field
    info = {
        "id": item.get("id", ""),
        "name": manifest.get("name", "Unknown"),
        "description": manifest.get("shortDescription", ""),
        "runtime": manifest.get("runtime", ""),
        "type": item_type,
    }

    # Add type-specific fields
    if item_type == "catalog_entry":
        # Check if configuration is needed based on:
        # 1. Required environment variables
        # 2. Remote servers needing URL configuration (hostname/urlTemplate without fixedURL)
        # 3. Remote servers with required headers
        env_vars = manifest.get("env", [])
        has_required_env = any(env.get("required", False) for env in env_vars)
        needs_url = _requires_url_configuration(manifest)
        has_required_headers = _has_required_headers(manifest)

        info["requires_configuration"] = has_required_env or needs_url or has_required_headers
        info["needs_url"] = needs_url
    else:  # multi_user_server
        info["configured"] = item.get("configured", False)
        info["needs_url"] = item.get("needsURL", False)
        info["deployment_status"] = item.get("deploymentStatus", "")
        # Construct connect URL using the standard mcp-connect format
        # Multi-user servers use the server ID as the connection identifier
        server_id = item.get("id", "")
        info["connect_url"] = f"{config.obot_server_url}/mcp-connect/{server_id}" if server_id else ""

    return info


def _filter_by_runtime(
    items: List[Dict[str, Any]], runtime_filter: Optional[str]
) -> List[Dict[str, Any]]:
    """
    Filter items by runtime type.

    Args:
        items: List of server items
        runtime_filter: Runtime to filter by (uvx, npx, containerized, remote, composite)

    Returns:
        Filtered list of items
    """
    if not runtime_filter:
        return items

    runtime_filter_lower = runtime_filter.lower()
    return [
        item
        for item in items
        if item.get("manifest", {}).get("runtime", "").lower() == runtime_filter_lower
    ]


def _search_items(items: List[Dict[str, Any]], query: str) -> List[Dict[str, Any]]:
    """
    Search items by query string in name and description.

    Args:
        items: List of items to search
        query: Search term

    Returns:
        Filtered list of items matching query
    """
    query_lower = query.lower()
    results = []

    for item in items:
        manifest = item.get("manifest", {})
        name = manifest.get("name", "").lower()
        description = manifest.get("shortDescription", "").lower()

        if query_lower in name or query_lower in description:
            results.append(item)

    return results


async def list_mcp_servers_impl(
    include_entries: bool = True,
    include_servers: bool = True,
    runtime_filter: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """
    Implementation for listing MCP servers.

    Args:
        include_entries: Include catalog entries (single-user server templates)
        include_servers: Include multi-user servers (already deployed)
        runtime_filter: Filter by runtime: "uvx", "npx", "containerized", "remote", "composite"
        limit: Maximum number of results to return (default: 50)

    Returns:
        Dictionary with:
        - catalog_entries: List of catalog entry objects
        - multi_user_servers: List of multi-user server objects
        - total_count: Total number of results returned
    """
    catalog_entries = []
    multi_user_servers = []

    # Fetch catalog entries
    if include_entries:
        raw_entries = await obot_client.get_catalog_entries(limit=limit)
        filtered_entries = _filter_by_runtime(raw_entries, runtime_filter)
        catalog_entries = [
            _extract_server_info(entry, "catalog_entry")
            for entry in filtered_entries[:limit]
        ]

    # Fetch multi-user servers
    if include_servers:
        raw_servers = await obot_client.get_multi_user_servers(limit=limit)
        filtered_servers = _filter_by_runtime(raw_servers, runtime_filter)
        multi_user_servers = [
            _extract_server_info(server, "multi_user_server")
            for server in filtered_servers[:limit]
        ]

    return {
        "catalog_entries": catalog_entries,
        "multi_user_servers": multi_user_servers,
        "total_count": len(catalog_entries) + len(multi_user_servers),
    }


@mcp.tool()
async def obot_list_mcp_servers(
    include_entries: bool = True,
    include_servers: bool = True,
    runtime_filter: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """
    List all available MCP servers in Obot.

    Args:
        include_entries: Include catalog entries (single-user server templates)
        include_servers: Include multi-user servers (already deployed)
        runtime_filter: Filter by runtime: "uvx", "npx", "containerized", "remote", "composite"
        limit: Maximum number of results to return (default: 50)

    Returns:
        Dictionary with:
        - catalog_entries: List of catalog entry objects
        - multi_user_servers: List of multi-user server objects
        - total_count: Total number of results returned
    """
    return await list_mcp_servers_impl(
        include_entries, include_servers, runtime_filter, limit
    )


async def search_mcp_servers_impl(
    query: str, runtime_filter: Optional[str] = None, limit: int = 20
) -> Dict[str, Any]:
    """
    Implementation for searching MCP servers.

    Args:
        query: Search term (matches name and description)
        runtime_filter: Optional runtime filter: "uvx", "npx", "containerized", "remote", "composite"
        limit: Maximum number of results to return (default: 20)

    Returns:
        Dictionary with:
        - catalog_entries: List of matching catalog entry objects
        - multi_user_servers: List of matching multi-user server objects
        - total_count: Total number of results returned
        - query: The search query used
    """
    # Fetch all items (we need to search them)
    raw_entries = await obot_client.get_catalog_entries(limit=1000)
    raw_servers = await obot_client.get_multi_user_servers(limit=1000)

    # Search in catalog entries
    matching_entries = _search_items(raw_entries, query)
    filtered_entries = _filter_by_runtime(matching_entries, runtime_filter)
    catalog_entries = [
        _extract_server_info(entry, "catalog_entry")
        for entry in filtered_entries[:limit]
    ]

    # Search in multi-user servers
    matching_servers = _search_items(raw_servers, query)
    filtered_servers = _filter_by_runtime(matching_servers, runtime_filter)
    multi_user_servers = [
        _extract_server_info(server, "multi_user_server")
        for server in filtered_servers[:limit]
    ]

    return {
        "catalog_entries": catalog_entries,
        "multi_user_servers": multi_user_servers,
        "total_count": len(catalog_entries) + len(multi_user_servers),
        "query": query,
    }


@mcp.tool()
async def obot_search_mcp_servers(
    query: str, runtime_filter: Optional[str] = None, limit: int = 20
) -> Dict[str, Any]:
    """
    Search for MCP servers by keyword.

    Args:
        query: Search term (matches name and description)
        runtime_filter: Optional runtime filter: "uvx", "npx", "containerized", "remote", "composite"
        limit: Maximum number of results to return (default: 20)

    Returns:
        Dictionary with:
        - catalog_entries: List of matching catalog entry objects
        - multi_user_servers: List of matching multi-user server objects
        - total_count: Total number of results returned
        - query: The search query used
    """
    return await search_mcp_servers_impl(query, runtime_filter, limit)


async def get_mcp_server_connection_impl(server_id: str) -> Dict[str, Any]:
    """
    Implementation for getting MCP server connection information.

    Args:
        server_id: The server or catalog entry ID

    Returns:
        Dictionary with connection status and information:
        - status: "available", "requires_configuration", "not_ready", or "not_found"
        - connect_url: Connection URL (if available)
        - configure_url: Configuration URL (if configuration needed)
        - deployment_status: Deployment status (if not ready)
        - message: Human-readable status message
    """
    # Try to get as catalog entry first
    catalog_entry = await obot_client.get_catalog_entry(server_id)

    if catalog_entry:
        # Check if requires configuration based on:
        # 1. Required environment variables
        # 2. Remote servers needing URL configuration (hostname/urlTemplate without fixedURL)
        # 3. Remote servers with required headers
        manifest = catalog_entry.get("manifest", {})
        env_vars = manifest.get("env", [])
        has_required_env = any(env.get("required", False) for env in env_vars)
        needs_url = _requires_url_configuration(manifest)
        has_required_headers = _has_required_headers(manifest)

        if has_required_env or needs_url or has_required_headers:
            configure_url = f"{config.obot_server_url}/mcp-servers/c/{server_id}"
            # Build a descriptive message based on what's needed
            reasons = []
            if has_required_env:
                reasons.append("environment variables")
            if needs_url:
                reasons.append("server URL")
            if has_required_headers:
                reasons.append("authentication headers")
            reason_str = ", ".join(reasons)
            return {
                "status": "requires_configuration",
                "configure_url": configure_url,
                "needs_url": needs_url,
                "message": f"Server requires configuration ({reason_str}). Please visit {configure_url} to configure.",
            }

        # No configuration required - return direct connection URL
        # Obot will automatically deploy the server when the user connects
        # Connection URLs use the /mcp-connect/{id} format
        connect_url = f"{config.obot_server_url}/mcp-connect/{server_id}"
        return {
            "status": "available",
            "connect_url": connect_url,
            "message": "Server is ready to connect.",
        }

    # Try to get as multi-user server
    server = await obot_client.get_multi_user_server(server_id)

    if server:
        configured = server.get("configured", False)
        needs_url = server.get("needsURL", False)

        # Check if server is ready
        if not configured or needs_url:
            configure_url = f"{config.obot_server_url}/mcp-servers/s/{server_id}"
            # Build message based on what's needed
            if needs_url:
                message = f"Server requires URL configuration. Please visit {configure_url} to update the server URL."
            else:
                message = f"Server requires configuration. Please visit {configure_url} to configure required settings."
            return {
                "status": "requires_configuration",
                "configure_url": configure_url,
                "needs_url": needs_url,
                "message": message,
            }

        # Construct connect URL using the standard mcp-connect format
        connect_url = f"{config.obot_server_url}/mcp-connect/{server_id}"
        return {
            "status": "available",
            "connect_url": connect_url,
            "message": "Server is ready to connect.",
        }

    # Server not found
    return {
        "status": "not_found",
        "message": f"No server or catalog entry found with ID: {server_id}",
    }


@mcp.tool()
async def obot_get_mcp_server_connection(server_id: str) -> Dict[str, Any]:
    """
    Get connection information for an MCP server.

    Args:
        server_id: The server or catalog entry ID

    Returns:
        Dictionary with connection status and information:
        - status: "available", "requires_configuration", "not_ready", or "not_found"
        - connect_url: Connection URL (if available)
        - configure_url: Configuration URL (if configuration needed)
        - deployment_status: Deployment status (if not ready)
        - message: Human-readable status message
    """
    return await get_mcp_server_connection_impl(server_id)
