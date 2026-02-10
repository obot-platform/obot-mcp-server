"""Async HTTP client for Obot API."""

from typing import Any, Dict, List, Optional

import httpx
from fastmcp.server.dependencies import get_http_request

from .config import config


class ObotClient:
    """Async client for interacting with Obot API."""

    def __init__(self, base_url: Optional[str] = None):
        """
        Initialize the Obot API client.

        Args:
            base_url: Obot server base URL (defaults to config.obot_server_url)
        """
        self.base_url = base_url or config.obot_server_url
        self._client: Optional[httpx.AsyncClient] = None

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authorization headers forwarded from the incoming request."""
        try:
            request = get_http_request()
            auth = request.headers.get("authorization")
            if auth:
                return {"Authorization": auth}
        except (RuntimeError, LookupError):
            pass
        return {}

    @property
    def client(self) -> httpx.AsyncClient:
        """Get or create the async HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=30.0,
            )
        return self._client

    async def close(self):
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def get_catalog_entries(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get all MCP server catalog entries (single-user templates).

        Args:
            limit: Maximum number of entries to return

        Returns:
            List of catalog entry dictionaries
        """
        response = await self.client.get(
            "/api/all-mcps/entries", headers=self._get_auth_headers()
        )
        response.raise_for_status()
        data = response.json()

        # Extract items from response, handle pagination if needed
        items = data.get("items", [])
        return items[:limit]

    async def get_catalog_entry(self, entry_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific catalog entry by ID.

        Args:
            entry_id: The catalog entry ID

        Returns:
            Catalog entry dictionary or None if not found
        """
        try:
            response = await self.client.get(
                f"/api/all-mcps/entries/{entry_id}",
                headers=self._get_auth_headers(),
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return None
            raise

    async def get_multi_user_servers(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get all multi-user MCP servers.

        Args:
            limit: Maximum number of servers to return

        Returns:
            List of server dictionaries
        """
        response = await self.client.get(
            "/api/all-mcps/servers", headers=self._get_auth_headers()
        )
        response.raise_for_status()
        data = response.json()

        # Extract items from response, handle pagination if needed
        items = data.get("items", [])
        return items[:limit]

    async def get_multi_user_server(self, server_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific multi-user server by ID.

        Args:
            server_id: The server ID

        Returns:
            Server dictionary or None if not found
        """
        try:
            response = await self.client.get(
                f"/api/all-mcps/servers/{server_id}",
                headers=self._get_auth_headers(),
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return None
            raise

    async def list_user_mcp_servers(self) -> List[Dict[str, Any]]:
        """
        List the current user's MCP servers.

        Returns:
            List of user server dictionaries
        """
        response = await self.client.get(
            "/api/mcp-servers", headers=self._get_auth_headers()
        )
        response.raise_for_status()
        data = response.json()
        return data.get("items", [])

    async def create_user_mcp_server(
        self, catalog_entry_id: str, url: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create a user MCP server from a catalog entry.

        Args:
            catalog_entry_id: The catalog entry ID to create from
            url: Optional URL for hostname-constrained remote servers

        Returns:
            Created server dictionary
        """
        body: Dict[str, Any] = {"catalogEntryID": catalog_entry_id}
        if url:
            body["manifest"] = {"remoteConfig": {"url": url}}

        response = await self.client.post(
            "/api/mcp-servers", json=body, headers=self._get_auth_headers()
        )
        response.raise_for_status()
        return response.json()

    async def configure_user_mcp_server(
        self, server_id: str, config: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Configure a user MCP server with environment variables and headers.

        Args:
            server_id: The server ID
            config: Flat dictionary of key-value pairs for configuration

        Returns:
            Response dictionary
        """
        response = await self.client.post(
            f"/api/mcp-servers/{server_id}/configure",
            json=config,
            headers=self._get_auth_headers(),
        )
        response.raise_for_status()
        return response.json()

    async def update_user_mcp_server_url(
        self, server_id: str, url: str
    ) -> Dict[str, Any]:
        """
        Update the URL of a user MCP server.

        Args:
            server_id: The server ID
            url: The new URL

        Returns:
            Response dictionary
        """
        response = await self.client.post(
            f"/api/mcp-servers/{server_id}/update-url",
            json={"url": url},
            headers=self._get_auth_headers(),
        )
        response.raise_for_status()
        return response.json()

