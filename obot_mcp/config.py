"""Configuration for Obot MCP Server."""

import os


class Config:
    """Configuration settings for the Obot MCP server."""

    def __init__(self):
        self.obot_server_url = os.getenv("OBOT_URL", "http://localhost:8080")

        # Ensure URL doesn't end with slash
        if self.obot_server_url.endswith("/"):
            self.obot_server_url = self.obot_server_url[:-1]


# Global config instance
config = Config()
