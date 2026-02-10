"""Configuration for Obot MCP Server."""

import os
from typing import Optional


class Config:
    """Configuration settings for the Obot MCP server."""

    def __init__(self):
        self.obot_server_url = os.getenv("OBOT_SERVER_URL", "http://localhost:8080")
        self.obot_token: Optional[str] = os.getenv("OBOT_TOKEN")

        # Ensure URL doesn't end with slash
        if self.obot_server_url.endswith("/"):
            self.obot_server_url = self.obot_server_url[:-1]

    @property
    def has_token(self) -> bool:
        """Check if authentication token is configured."""
        return self.obot_token is not None and len(self.obot_token) > 0


# Global config instance
config = Config()
