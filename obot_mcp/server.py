"""FastMCP server with tools for Obot MCP server discovery and connection."""

import asyncio
import re
import uuid
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import urlparse

import httpx
from fastmcp import Context, FastMCP
from fastmcp.server.context import (
    AcceptedElicitation,
    CancelledElicitation,
    DeclinedElicitation,
)
from mcp import types as mcp_types
from pydantic import Field, create_model

from .client import ObotClient
from .config import config

# Create the FastMCP server
mcp = FastMCP("obot-mcp-server")

# This server exposes only tools. Remove prompt/resource handlers so the
# initialize response does not advertise unsupported capabilities.
for request_type in (
    mcp_types.ListPromptsRequest,
    mcp_types.GetPromptRequest,
    mcp_types.ListResourcesRequest,
    mcp_types.ListResourceTemplatesRequest,
    mcp_types.ReadResourceRequest,
):
    mcp._mcp_server.request_handlers.pop(request_type, None)

# Create a shared client instance
obot_client = ObotClient()


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
        requirements = _extract_configuration_requirements(manifest)
        has_config = bool(
            requirements["required_parameters"]
            or requirements["optional_parameters"]
            or requirements.get("url_configuration")
        )
        info["requires_configuration"] = has_config
        info["needs_url"] = requirements.get("url_configuration") is not None
    else:  # multi_user_server
        info["configured"] = item.get("configured", False)
        info["needs_url"] = item.get("needsURL", False)
        info["deployment_status"] = item.get("deploymentStatus", "")
        # Construct connect URL using the standard mcp-connect format
        # Multi-user servers use the server ID as the connection identifier
        server_id = item.get("id", "")
        info["connect_url"] = (
            f"{config.obot_server_url}/mcp-connect/{server_id}" if server_id else ""
        )

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
    Search items by query string in name, short description, and description.

    Results are ordered by match priority:
    1. Title (name) matches
    2. Short description matches
    3. Description matches

    Args:
        items: List of items to search
        query: Search term

    Returns:
        Filtered list of items matching query, ordered by match priority
    """
    query_lower = query.lower()
    title_matches = []
    short_desc_matches = []
    desc_matches = []

    for item in items:
        manifest = item.get("manifest", {})
        name = manifest.get("name", "").lower()
        short_description = manifest.get("shortDescription", "").lower()
        description = manifest.get("description", "").lower()

        if query_lower in name:
            title_matches.append(item)
        elif query_lower in short_description:
            short_desc_matches.append(item)
        elif query_lower in description:
            desc_matches.append(item)

    return title_matches + short_desc_matches + desc_matches


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


def _extract_configuration_requirements(manifest: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse a catalog entry manifest and return structured configuration requirements.

    Args:
        manifest: The catalog entry manifest

    Returns:
        Dictionary with required_parameters, optional_parameters,
        url_configuration, and has_oauth_requirement
    """
    required_parameters: List[Dict[str, Any]] = []
    optional_parameters: List[Dict[str, Any]] = []

    # Collect env var names we've already seen (to avoid duplicating template vars)
    seen_keys: set = set()

    # Process environment variables
    for env in manifest.get("env", []):
        # Skip env vars with pre-set static values
        if env.get("value"):
            continue

        key = env.get("key", env.get("name", ""))
        seen_keys.add(key)
        param = {
            "key": key,
            "name": env.get("name", key),
            "description": env.get("description", ""),
            "sensitive": env.get("sensitive", False),
            "type": "env",
            "file": env.get("file", False),
        }

        if env.get("required", False):
            required_parameters.append(param)
        else:
            optional_parameters.append(param)

    # Process remote config headers
    remote_config = manifest.get("remoteConfig", {})
    if manifest.get("runtime") == "remote" and remote_config:
        for header in remote_config.get("headers", []):
            # Skip headers with pre-set static values
            if header.get("value"):
                continue

            key = header.get("key", header.get("name", ""))
            seen_keys.add(key)
            param = {
                "key": key,
                "name": header.get("name", key),
                "description": header.get("description", ""),
                "sensitive": header.get("sensitive", False),
                "type": "header",
            }
            if header.get("prefix"):
                param["prefix"] = header["prefix"]

            if header.get("required", False):
                required_parameters.append(param)
            else:
                optional_parameters.append(param)

    # Determine URL configuration
    url_configuration = None
    if manifest.get("runtime") == "remote" and remote_config:
        if not remote_config.get("fixedURL"):
            hostname = remote_config.get("hostname")
            url_template = remote_config.get("urlTemplate")

            if hostname:
                url_configuration = {
                    "type": "hostname",
                    "hostname": hostname,
                }
            elif url_template:
                url_configuration = {
                    "type": "template",
                    "template": url_template,
                }

                # Extract ${VAR_NAME} references from the template
                template_vars = re.findall(r"\$\{(\w+)\}", url_template)
                for var_name in template_vars:
                    if var_name not in seen_keys:
                        seen_keys.add(var_name)
                        required_parameters.append(
                            {
                                "key": var_name,
                                "name": var_name,
                                "description": f"Value for template variable {var_name}",
                                "sensitive": False,
                                "type": "env",
                                "file": False,
                            }
                        )

    # Check for OAuth requirement
    has_oauth_requirement = bool(remote_config.get("staticOAuthRequired", False))

    return {
        "required_parameters": required_parameters,
        "optional_parameters": optional_parameters,
        "url_configuration": url_configuration,
        "has_oauth_requirement": has_oauth_requirement,
    }


async def _find_existing_user_server(
    entry_id: str,
) -> Optional[Dict[str, Any]]:
    """
    Find an existing user server created from a specific catalog entry.

    Args:
        entry_id: The catalog entry ID

    Returns:
        The user server dictionary if found, None otherwise
    """
    servers = await obot_client.list_user_mcp_servers()
    for server in servers:
        if server.get("catalogEntryID") == entry_id:
            return server
    return None


def _validate_hostname(url: str, hostname_pattern: str) -> bool:
    """
    Validate that a URL matches a hostname constraint.

    Supports exact match and wildcard patterns like *.example.com.

    Args:
        url: The URL to validate
        hostname_pattern: The hostname constraint (exact or *.suffix)

    Returns:
        True if the URL matches the hostname constraint
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return False
    except Exception:
        return False

    if hostname_pattern.startswith("*."):
        suffix = hostname_pattern[1:]  # e.g., ".example.com"
        return host.endswith(suffix) or host == hostname_pattern[2:]
    else:
        return host == hostname_pattern


def _build_elicitation_model(
    requirements: Dict[str, Any],
    url_configuration: Optional[Dict[str, Any]],
) -> type:
    """
    Dynamically build a Pydantic model class for ctx.elicit().

    Args:
        requirements: Output from _extract_configuration_requirements
        url_configuration: URL configuration dict or None

    Returns:
        A dynamically-created Pydantic model class
    """
    fields: Dict[str, Any] = {}

    for param in requirements.get("required_parameters", []):
        extra = {"format": "password"} if param.get("sensitive") else None
        fields[param["key"]] = (
            str,
            Field(
                title=param.get("name", param["key"]),
                description=param.get("description", ""),
                json_schema_extra=extra,
            ),
        )

    for param in requirements.get("optional_parameters", []):
        extra = {"format": "password"} if param.get("sensitive") else None
        fields[param["key"]] = (
            str,
            Field(
                default="",
                title=param.get("name", param["key"]),
                description=param.get("description", ""),
                json_schema_extra=extra,
            ),
        )

    if url_configuration and url_configuration.get("type") == "hostname":
        hostname = url_configuration.get("hostname", "")
        fields["url"] = (
            str,
            Field(
                title="Server URL",
                description=f"URL for the server (must match hostname: {hostname})",
            ),
        )

    return create_model("ConfigurationForm", **fields)


async def _handle_oauth_elicitation(
    ctx: Context, name: str, oauth_url: str, server_id: str
) -> bool:
    """
    Present OAuth elicitation to user and wait for token storage.

    Uses MCP URL mode elicitation to direct the user to the OAuth
    authorization URL in their browser. After the user accepts,
    polls the oauth-url endpoint until it returns empty (meaning
    the token has been stored by Obot).

    Args:
        ctx: FastMCP context
        name: Server name for display
        oauth_url: OAuth authorization URL
        server_id: The MCP server ID, used to poll for token completion

    Returns:
        True if OAuth completed (user accepted), False if cancelled/declined
    """
    message = (
        f"The MCP server '{name}' requires authentication with an external service.\n\n"
        f"Please visit the URL below to authenticate, "
        f"then return here and accept to continue."
    )

    # Build the URL mode elicitation params with _meta containing the OAuth URL.
    # Nanobot's ElicitRequest struct only preserves message, requestedSchema, and _meta
    # when forwarding elicitations to the UI — the standard MCP "mode" and "url" fields
    # are dropped. Including the URL in _meta with the "ai.nanobot.meta/oauth-url" key
    # ensures the UI can detect and display the OAuth URL correctly.
    params = mcp_types.ElicitRequestURLParams(
        message=message,
        url=oauth_url,
        elicitationId=str(uuid.uuid4()),
    )
    params.meta = mcp_types.RequestParams.Meta(
        **{
            "ai.nanobot.meta/oauth-url": oauth_url,
            "ai.nanobot.meta/server-name": name,
        }
    )

    result = await ctx.session.send_request(
        mcp_types.ServerRequest(
            mcp_types.ElicitRequest(params=params),
        ),
        mcp_types.ElicitResult,
    )

    if result.action != "accept":
        return False

    # Poll until Obot has stored the OAuth token.
    # The oauth-url endpoint returns a URL when auth is still needed,
    # and empty/None when the token has been stored.
    max_attempts = 60
    poll_interval = 2  # seconds
    for _ in range(max_attempts):
        try:
            url = await obot_client.get_mcp_server_oauth_url(server_id)
            if not url:
                return True
        except Exception:
            # If the endpoint errors, assume we should keep waiting
            pass
        await asyncio.sleep(poll_interval)

    # Timed out waiting for token, but user did accept — proceed anyway
    return True


@mcp.tool()
async def obot_connect_to_mcp_server(
    server_id: str,
    ctx: Context,
) -> Dict[str, Any]:
    """
    Connect to an MCP server by catalog entry ID or multi-user server ID.

    Handles the full connection flow end-to-end: configure, launch, OAuth,
    and return a connect_url. For catalog entries, reads configuration
    requirements, presents a form to collect necessary values (API keys,
    URLs, etc.), creates/configures the server, and validates launch.
    For multi-user servers, checks configuration status and handles OAuth.

    If the server requires OAuth authentication, the user will be
    prompted to visit an authentication URL in their browser before
    continuing.

    Args:
        server_id: The catalog entry ID or multi-user server ID

    Returns:
        Dictionary with connection status and information
    """
    # --- Try catalog entry first ---
    try:
        catalog_entry = await obot_client.get_catalog_entry(server_id)
    except (httpx.HTTPStatusError, httpx.TimeoutException) as e:
        return {"status": "error", "message": f"Failed to fetch catalog entry: {e}"}

    if catalog_entry:
        return await _handle_catalog_entry_connection(server_id, catalog_entry, ctx)

    # --- Fall back to multi-user server ---
    try:
        multi_user_server = await obot_client.get_multi_user_server(server_id)
    except (httpx.HTTPStatusError, httpx.TimeoutException) as e:
        return {"status": "error", "message": f"Failed to fetch server: {e}"}

    if multi_user_server:
        return await _handle_multi_user_server_connection(
            server_id, multi_user_server, ctx
        )

    # --- Not found ---
    return {
        "status": "not_found",
        "message": f"No catalog entry or server found with ID: {server_id}",
    }


async def _handle_multi_user_server_connection(
    server_id: str, server: Dict[str, Any], ctx: Context
) -> Dict[str, Any]:
    """Handle connection flow for a multi-user server."""
    configured = server.get("configured", False)
    needs_url = server.get("needsURL", False)
    name = server.get("manifest", {}).get("name", "Unknown")

    if not configured or needs_url:
        configure_url = f"{config.obot_server_url}/mcp-servers/s/{server_id}"
        if needs_url:
            message = f"Server '{name}' requires URL configuration. Please visit {configure_url} to update the server URL."
        else:
            message = f"Server '{name}' requires configuration. Please visit {configure_url} to configure required settings."
        return {
            "status": "error",
            "configure_url": configure_url,
            "message": message,
        }

    # Check for OAuth requirement
    try:
        oauth_url = await obot_client.get_mcp_server_oauth_url(server_id)
        if oauth_url:
            oauth_success = await _handle_oauth_elicitation(
                ctx, name, oauth_url, server_id
            )
            if not oauth_success:
                return {
                    "status": "cancelled",
                    "message": "OAuth authentication was cancelled by the user.",
                }
    except (httpx.HTTPStatusError, httpx.TimeoutException):
        pass

    connect_url = f"{config.obot_server_url}/mcp-connect/{server_id}"
    return {
        "status": "available",
        "connect_url": connect_url,
        "message": f"Server '{name}' is ready to connect.",
    }


async def _handle_catalog_entry_connection(
    entry_id: str, catalog_entry: Dict[str, Any], ctx: Context
) -> Dict[str, Any]:
    """Handle connection flow for a catalog entry."""
    manifest = catalog_entry.get("manifest", {})
    name = manifest.get("name", "Unknown")

    # 1. Reject composite servers
    if manifest.get("runtime") == "composite":
        return {
            "status": "error",
            "message": "Composite servers cannot be configured through this tool. "
            "Please use the Obot web UI instead.",
        }

    # 2. Check OAuth admin requirement
    remote_config = manifest.get("remoteConfig", {})
    if remote_config.get("staticOAuthRequired") and not catalog_entry.get(
        "oauthCredentialConfigured"
    ):
        return {
            "status": "error",
            "message": f"Server '{name}' requires OAuth configuration that must be set up by an administrator first.",
        }

    # 3. Check for existing configured server
    try:
        existing_server = await _find_existing_user_server(entry_id)
    except (httpx.HTTPStatusError, httpx.TimeoutException) as e:
        return {
            "status": "error",
            "message": f"Failed to check for existing servers: {e}",
        }

    if existing_server and existing_server.get("configured"):
        user_server_id = existing_server.get("id", "")

        # Check for OAuth requirement even for already configured servers
        try:
            oauth_url = await obot_client.get_mcp_server_oauth_url(user_server_id)
            if oauth_url:
                oauth_success = await _handle_oauth_elicitation(
                    ctx, name, oauth_url, user_server_id
                )
                if not oauth_success:
                    return {
                        "status": "cancelled",
                        "message": "OAuth authentication was cancelled by the user.",
                    }
        except (httpx.HTTPStatusError, httpx.TimeoutException) as e:
            return {
                "status": "error",
                "message": f"Failed to check OAuth requirements: {e}",
            }

        return {
            "status": "already_configured",
            "server_id": user_server_id,
            "connect_url": f"{config.obot_server_url}/mcp-connect/{user_server_id}",
            "message": f"Server '{name}' is already configured and ready to connect.",
        }

    # 4. Extract configuration requirements
    requirements = _extract_configuration_requirements(manifest)
    url_config = requirements.get("url_configuration")

    # 5. If no configuration needed, create server directly
    has_params = (
        requirements["required_parameters"] or requirements["optional_parameters"]
    )
    needs_url = url_config is not None and url_config.get("type") == "hostname"

    if not has_params and not needs_url:
        try:
            if existing_server:
                user_server_id = existing_server.get("id", "")
            else:
                created = await obot_client.create_user_mcp_server(entry_id)
                user_server_id = created.get("id", "")

            # Launch validation
            try:
                launch_result = await obot_client.launch_user_mcp_server(user_server_id)
                if not launch_result.get("success"):
                    return {
                        "status": "error",
                        "message": f"Server failed to launch: {launch_result.get('message', 'unknown error')}",
                    }
            except Exception:
                pass  # Launch endpoint may not exist yet

            # Check for OAuth requirement
            oauth_url = await obot_client.get_mcp_server_oauth_url(user_server_id)
            if oauth_url:
                oauth_success = await _handle_oauth_elicitation(
                    ctx, name, oauth_url, user_server_id
                )
                if not oauth_success:
                    return {
                        "status": "cancelled",
                        "message": "OAuth authentication was cancelled by the user.",
                    }

            return {
                "status": "configured",
                "server_id": user_server_id,
                "connect_url": f"{config.obot_server_url}/mcp-connect/{user_server_id}",
                "message": f"Server '{name}' created and ready to connect.",
            }
        except (httpx.HTTPStatusError, httpx.TimeoutException) as e:
            return {"status": "error", "message": f"Failed to create server: {e}"}

    # 6. Build elicitation model
    ConfigModel = _build_elicitation_model(requirements, url_config)

    # 7. Elicit from user
    result = await ctx.elicit(
        f"Please provide the configuration for {name}:", ConfigModel
    )

    # 8. Handle elicitation result
    if isinstance(result, (DeclinedElicitation, CancelledElicitation)):
        return {
            "status": "cancelled",
            "message": "Configuration was cancelled by the user.",
        }

    # result is AcceptedElicitation
    elicited_data = result.data

    # 9. Separate values into config dict and url
    config_dict: Dict[str, str] = {}
    url_value: Optional[str] = None

    if isinstance(elicited_data, dict):
        data_dict = elicited_data
    else:
        # Pydantic model - convert to dict
        data_dict = (
            elicited_data.model_dump()
            if hasattr(elicited_data, "model_dump")
            else dict(elicited_data)
        )

    for key, value in data_dict.items():
        if key == "url" and needs_url:
            url_value = value
        elif value:  # Only include non-empty values
            config_dict[key] = value

    # Validate hostname if applicable
    if url_value and url_config and url_config.get("type") == "hostname":
        hostname_pattern = url_config.get("hostname", "")
        if not _validate_hostname(url_value, hostname_pattern):
            return {
                "status": "error",
                "message": f"URL '{url_value}' does not match the required hostname pattern: {hostname_pattern}",
            }

    # 10. Find or create server
    try:
        if existing_server:
            user_server_id = existing_server.get("id", "")
        else:
            created = await obot_client.create_user_mcp_server(
                entry_id, url=url_value if needs_url else None
            )
            user_server_id = created.get("id", "")
    except (httpx.HTTPStatusError, httpx.TimeoutException) as e:
        return {"status": "error", "message": f"Failed to create server: {e}"}

    # 11. Configure server with collected values
    if config_dict:
        try:
            await obot_client.configure_user_mcp_server(user_server_id, config_dict)
        except (httpx.HTTPStatusError, httpx.TimeoutException) as e:
            return {
                "status": "error",
                "message": f"Failed to configure server: {e}",
            }

    # Check and handle OAuth requirement
    oauth_url = await obot_client.get_mcp_server_oauth_url(user_server_id)
    if oauth_url:
        oauth_success = await _handle_oauth_elicitation(
            ctx, name, oauth_url, user_server_id
        )
        if not oauth_success:
            return {
                "status": "cancelled",
                "message": "OAuth authentication was cancelled by the user.",
            }

    # 12. Launch validation
    try:
        launch_result = await obot_client.launch_user_mcp_server(user_server_id)
        if not launch_result.get("success"):
            return {
                "status": "error",
                "message": f"Server failed to launch: {launch_result.get('message', 'unknown error')}",
            }
    except Exception:
        pass  # Launch endpoint may not exist yet

    # 13. Update URL if needed for existing server
    if url_value and existing_server:
        try:
            await obot_client.update_user_mcp_server_url(user_server_id, url_value)
        except (httpx.HTTPStatusError, httpx.TimeoutException) as e:
            return {
                "status": "error",
                "message": f"Failed to update server URL: {e}",
            }

    # 14. Return success
    return {
        "status": "configured",
        "server_id": user_server_id,
        "connect_url": f"{config.obot_server_url}/mcp-connect/{user_server_id}",
        "message": f"Server '{name}' has been configured and is ready to connect.",
    }
