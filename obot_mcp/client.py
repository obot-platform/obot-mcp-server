"""Async HTTP client for Obot API."""

from typing import Any, Dict, List, Optional

import httpx

from .config import config


class ObotClient:
    """Async client for interacting with Obot API."""

    def __init__(self, base_url: Optional[str] = None, token: Optional[str] = None):
        """
        Initialize the Obot API client.

        Args:
            base_url: Obot server base URL (defaults to config.obot_server_url)
            token: Bearer token for authentication (defaults to config.obot_token)
        """
        self.base_url = base_url or config.obot_server_url
        self.token = token or config.obot_token
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def client(self) -> httpx.AsyncClient:
        """Get or create the async HTTP client."""
        if self._client is None:
            headers = {}
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"

            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=headers,
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
        response = await self.client.get(f"/api/all-mcps/entries")
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
            response = await self.client.get(f"/api/all-mcps/entries/{entry_id}")
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
        response = await self.client.get(f"/api/all-mcps/servers")
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
            response = await self.client.get(f"/api/all-mcps/servers/{server_id}")
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return None
            raise

