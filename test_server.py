"""Tests for obot_configure_catalog_entry tool and related functions."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
from fastmcp.server.context import AcceptedElicitation, DeclinedElicitation, CancelledElicitation

from obot_mcp.server import (
    _extract_configuration_requirements,
    _validate_hostname,
    _build_elicitation_model,
    _find_existing_user_server,
    obot_configure_catalog_entry as obot_configure_catalog_entry_tool,
    obot_client,
)
from obot_mcp.client import ObotClient

# The @mcp.tool() decorator wraps the function into a FunctionTool object.
# Access the underlying async function via .fn for direct testing.
obot_configure_catalog_entry = obot_configure_catalog_entry_tool.fn


# --- Test _extract_configuration_requirements ---


class TestExtractConfigurationRequirements:
    def test_required_env_vars(self):
        manifest = {
            "env": [
                {"name": "API_KEY", "description": "API key", "required": True, "sensitive": True},
                {"name": "OPTIONAL_VAR", "description": "Optional", "required": False},
            ]
        }
        result = _extract_configuration_requirements(manifest)
        assert len(result["required_parameters"]) == 1
        assert result["required_parameters"][0]["key"] == "API_KEY"
        assert result["required_parameters"][0]["sensitive"] is True
        assert result["required_parameters"][0]["type"] == "env"
        assert len(result["optional_parameters"]) == 1
        assert result["optional_parameters"][0]["key"] == "OPTIONAL_VAR"

    def test_static_env_vars_excluded(self):
        manifest = {
            "env": [
                {"name": "STATIC_VAR", "value": "preset_value", "required": True},
                {"name": "USER_VAR", "description": "Needs input", "required": True},
            ]
        }
        result = _extract_configuration_requirements(manifest)
        assert len(result["required_parameters"]) == 1
        assert result["required_parameters"][0]["key"] == "USER_VAR"

    def test_remote_headers(self):
        manifest = {
            "runtime": "remote",
            "remoteConfig": {
                "headers": [
                    {"name": "X-API-Key", "description": "API key header", "required": True, "sensitive": True},
                    {"name": "X-Optional", "description": "Optional header", "required": False},
                ]
            },
        }
        result = _extract_configuration_requirements(manifest)
        assert len(result["required_parameters"]) == 1
        assert result["required_parameters"][0]["type"] == "header"
        assert len(result["optional_parameters"]) == 1
        assert result["optional_parameters"][0]["type"] == "header"

    def test_static_headers_excluded(self):
        manifest = {
            "runtime": "remote",
            "remoteConfig": {
                "headers": [
                    {"name": "X-Static", "value": "preset", "required": True},
                    {"name": "X-User", "description": "User header", "required": True},
                ]
            },
        }
        result = _extract_configuration_requirements(manifest)
        assert len(result["required_parameters"]) == 1
        assert result["required_parameters"][0]["key"] == "X-User"

    def test_header_prefix(self):
        manifest = {
            "runtime": "remote",
            "remoteConfig": {
                "headers": [
                    {"name": "Authorization", "required": True, "prefix": "Bearer "},
                ]
            },
        }
        result = _extract_configuration_requirements(manifest)
        assert result["required_parameters"][0]["prefix"] == "Bearer "

    def test_hostname_url_config(self):
        manifest = {
            "runtime": "remote",
            "remoteConfig": {"hostname": "*.example.com"},
        }
        result = _extract_configuration_requirements(manifest)
        assert result["url_configuration"]["type"] == "hostname"
        assert result["url_configuration"]["hostname"] == "*.example.com"

    def test_template_url_config(self):
        manifest = {
            "runtime": "remote",
            "remoteConfig": {"urlTemplate": "https://${HOST}/api/v1"},
        }
        result = _extract_configuration_requirements(manifest)
        assert result["url_configuration"]["type"] == "template"
        assert result["url_configuration"]["template"] == "https://${HOST}/api/v1"

    def test_template_var_extraction(self):
        manifest = {
            "runtime": "remote",
            "remoteConfig": {"urlTemplate": "https://${HOST}/api/${VERSION}"},
        }
        result = _extract_configuration_requirements(manifest)
        keys = [p["key"] for p in result["required_parameters"]]
        assert "HOST" in keys
        assert "VERSION" in keys

    def test_template_var_no_duplicate_with_env(self):
        manifest = {
            "runtime": "remote",
            "env": [{"name": "HOST", "required": True}],
            "remoteConfig": {"urlTemplate": "https://${HOST}/api"},
        }
        result = _extract_configuration_requirements(manifest)
        host_params = [p for p in result["required_parameters"] if p["key"] == "HOST"]
        assert len(host_params) == 1

    def test_fixed_url_no_url_config(self):
        manifest = {
            "runtime": "remote",
            "remoteConfig": {"fixedURL": True, "hostname": "example.com"},
        }
        result = _extract_configuration_requirements(manifest)
        assert result["url_configuration"] is None

    def test_no_url_config_for_non_remote(self):
        manifest = {
            "runtime": "uvx",
            "env": [{"name": "API_KEY", "required": True}],
        }
        result = _extract_configuration_requirements(manifest)
        assert result["url_configuration"] is None

    def test_oauth_detection(self):
        manifest = {
            "runtime": "remote",
            "remoteConfig": {"staticOAuthRequired": True},
        }
        result = _extract_configuration_requirements(manifest)
        assert result["has_oauth_requirement"] is True

    def test_no_oauth(self):
        manifest = {"runtime": "remote", "remoteConfig": {}}
        result = _extract_configuration_requirements(manifest)
        assert result["has_oauth_requirement"] is False

    def test_empty_manifest(self):
        result = _extract_configuration_requirements({})
        assert result["required_parameters"] == []
        assert result["optional_parameters"] == []
        assert result["url_configuration"] is None
        assert result["has_oauth_requirement"] is False

    def test_key_field_takes_precedence_over_name(self):
        manifest = {
            "runtime": "remote",
            "env": [
                {"name": "API Key", "key": "API_KEY", "description": "Key", "required": True},
            ],
            "remoteConfig": {
                "headers": [
                    {"name": "Vis Request Server", "key": "VIS_REQUEST_SERVER", "description": "Header", "required": True},
                ]
            },
        }
        result = _extract_configuration_requirements(manifest)
        env_param = [p for p in result["required_parameters"] if p["type"] == "env"][0]
        header_param = [p for p in result["required_parameters"] if p["type"] == "header"][0]
        # key field should be used for the dict key (credential lookup)
        assert env_param["key"] == "API_KEY"
        assert header_param["key"] == "VIS_REQUEST_SERVER"
        # name field should be preserved for display
        assert env_param["name"] == "API Key"
        assert header_param["name"] == "Vis Request Server"

    def test_file_flag_preserved(self):
        manifest = {
            "env": [
                {"name": "CERT", "required": True, "file": True},
            ]
        }
        result = _extract_configuration_requirements(manifest)
        assert result["required_parameters"][0]["file"] is True


# --- Test _validate_hostname ---


class TestValidateHostname:
    def test_exact_match(self):
        assert _validate_hostname("https://example.com/api", "example.com") is True

    def test_exact_mismatch(self):
        assert _validate_hostname("https://other.com/api", "example.com") is False

    def test_wildcard_match(self):
        assert _validate_hostname("https://sub.example.com/api", "*.example.com") is True

    def test_wildcard_base_match(self):
        assert _validate_hostname("https://example.com/api", "*.example.com") is True

    def test_wildcard_mismatch(self):
        assert _validate_hostname("https://sub.other.com/api", "*.example.com") is False

    def test_invalid_url(self):
        assert _validate_hostname("not-a-url", "example.com") is False

    def test_empty_url(self):
        assert _validate_hostname("", "example.com") is False

    def test_deep_subdomain_wildcard(self):
        assert _validate_hostname("https://a.b.example.com/api", "*.example.com") is True


# --- Test _build_elicitation_model ---


class TestBuildElicitationModel:
    def test_required_fields(self):
        requirements = {
            "required_parameters": [
                {"key": "API_KEY", "name": "API Key", "description": "Your API key"},
            ],
            "optional_parameters": [],
        }
        Model = _build_elicitation_model(requirements, None)
        fields = Model.model_fields
        assert "API_KEY" in fields
        assert fields["API_KEY"].is_required()

    def test_optional_fields(self):
        requirements = {
            "required_parameters": [],
            "optional_parameters": [
                {"key": "REGION", "name": "Region", "description": "Optional region"},
            ],
        }
        Model = _build_elicitation_model(requirements, None)
        fields = Model.model_fields
        assert "REGION" in fields
        assert not fields["REGION"].is_required()

    def test_sensitive_fields_get_password_format(self):
        requirements = {
            "required_parameters": [
                {"key": "API_KEY", "name": "API Key", "description": "Key", "sensitive": True},
                {"key": "REGION", "name": "Region", "description": "Region", "sensitive": False},
            ],
            "optional_parameters": [
                {"key": "SECRET", "name": "Secret", "description": "Optional secret", "sensitive": True},
            ],
        }
        Model = _build_elicitation_model(requirements, None)
        schema = Model.model_json_schema()
        assert schema["properties"]["API_KEY"]["format"] == "password"
        assert "format" not in schema["properties"]["REGION"]
        assert schema["properties"]["SECRET"]["format"] == "password"

    def test_url_field_with_hostname(self):
        requirements = {
            "required_parameters": [],
            "optional_parameters": [],
        }
        url_config = {"type": "hostname", "hostname": "*.example.com"}
        Model = _build_elicitation_model(requirements, url_config)
        fields = Model.model_fields
        assert "url" in fields
        assert fields["url"].is_required()

    def test_no_url_field_without_hostname(self):
        requirements = {
            "required_parameters": [],
            "optional_parameters": [],
        }
        url_config = {"type": "template", "template": "https://${HOST}/api"}
        Model = _build_elicitation_model(requirements, url_config)
        assert "url" not in Model.model_fields

    def test_combined_fields(self):
        requirements = {
            "required_parameters": [
                {"key": "API_KEY", "name": "API Key", "description": "Key"},
            ],
            "optional_parameters": [
                {"key": "REGION", "name": "Region", "description": "Region"},
            ],
        }
        url_config = {"type": "hostname", "hostname": "*.example.com"}
        Model = _build_elicitation_model(requirements, url_config)
        assert len(Model.model_fields) == 3
        assert "API_KEY" in Model.model_fields
        assert "REGION" in Model.model_fields
        assert "url" in Model.model_fields


# --- Test _find_existing_user_server ---


class TestFindExistingUserServer:
    @pytest.mark.asyncio
    async def test_found(self):
        mock_servers = [
            {"id": "s1", "catalogEntryID": "entry-1", "configured": True},
            {"id": "s2", "catalogEntryID": "entry-2", "configured": False},
        ]
        with patch.object(obot_client, "list_user_mcp_servers", new_callable=AsyncMock, return_value=mock_servers):
            result = await _find_existing_user_server("entry-1")
        assert result is not None
        assert result["id"] == "s1"

    @pytest.mark.asyncio
    async def test_not_found(self):
        mock_servers = [
            {"id": "s1", "catalogEntryID": "entry-1"},
        ]
        with patch.object(obot_client, "list_user_mcp_servers", new_callable=AsyncMock, return_value=mock_servers):
            result = await _find_existing_user_server("entry-999")
        assert result is None

    @pytest.mark.asyncio
    async def test_empty_list(self):
        with patch.object(obot_client, "list_user_mcp_servers", new_callable=AsyncMock, return_value=[]):
            result = await _find_existing_user_server("entry-1")
        assert result is None


# --- Test obot_configure_catalog_entry ---


def _make_ctx(elicit_result=None):
    """Create a mock Context for testing."""
    ctx = AsyncMock(spec=["elicit"])
    if elicit_result is not None:
        ctx.elicit = AsyncMock(return_value=elicit_result)
    return ctx


class TestConfigureCatalogEntry:
    @pytest.mark.asyncio
    async def test_not_found(self):
        ctx = _make_ctx()
        with patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, return_value=None):
            result = await obot_configure_catalog_entry(entry_id="missing", ctx=ctx)
        assert result["status"] == "not_found"

    @pytest.mark.asyncio
    async def test_composite_rejected(self):
        ctx = _make_ctx()
        entry = {"manifest": {"name": "Composite", "runtime": "composite"}}
        with patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, return_value=entry):
            result = await obot_configure_catalog_entry(entry_id="comp-1", ctx=ctx)
        assert result["status"] == "error"
        assert "Composite" in result["message"]

    @pytest.mark.asyncio
    async def test_oauth_blocked(self):
        ctx = _make_ctx()
        entry = {
            "manifest": {
                "name": "OAuth Server",
                "runtime": "remote",
                "remoteConfig": {
                    "staticOAuthRequired": True,
                    "oauthCredentialConfigured": False,
                },
            }
        }
        with patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, return_value=entry):
            result = await obot_configure_catalog_entry(entry_id="oauth-1", ctx=ctx)
        assert result["status"] == "error"
        assert "OAuth" in result["message"]

    @pytest.mark.asyncio
    async def test_already_configured(self):
        ctx = _make_ctx()
        entry = {"manifest": {"name": "Test Server", "runtime": "uvx", "env": []}}
        existing = {"id": "s1", "catalogEntryID": "entry-1", "configured": True}
        with (
            patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, return_value=entry),
            patch.object(obot_client, "list_user_mcp_servers", new_callable=AsyncMock, return_value=[existing]),
        ):
            result = await obot_configure_catalog_entry(entry_id="entry-1", ctx=ctx)
        assert result["status"] == "already_configured"
        assert result["server_id"] == "s1"

    @pytest.mark.asyncio
    async def test_no_config_needed_auto_create(self):
        ctx = _make_ctx()
        entry = {"manifest": {"name": "Simple Server", "runtime": "uvx", "env": []}}
        created = {"id": "new-1"}
        with (
            patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, return_value=entry),
            patch.object(obot_client, "list_user_mcp_servers", new_callable=AsyncMock, return_value=[]),
            patch.object(obot_client, "create_user_mcp_server", new_callable=AsyncMock, return_value=created),
        ):
            result = await obot_configure_catalog_entry(entry_id="entry-1", ctx=ctx)
        assert result["status"] == "configured"
        assert result["server_id"] == "new-1"

    @pytest.mark.asyncio
    async def test_elicitation_accept_flow(self):
        entry = {
            "manifest": {
                "name": "API Server",
                "runtime": "uvx",
                "env": [
                    {"name": "API_KEY", "description": "Key", "required": True, "sensitive": True},
                ],
            }
        }
        elicit_data = {"API_KEY": "my-secret-key"}
        elicit_result = AcceptedElicitation(data=elicit_data)
        ctx = _make_ctx(elicit_result)
        created = {"id": "new-2"}

        with (
            patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, return_value=entry),
            patch.object(obot_client, "list_user_mcp_servers", new_callable=AsyncMock, return_value=[]),
            patch.object(obot_client, "create_user_mcp_server", new_callable=AsyncMock, return_value=created),
            patch.object(obot_client, "configure_user_mcp_server", new_callable=AsyncMock, return_value={}) as mock_configure,
        ):
            result = await obot_configure_catalog_entry(entry_id="entry-1", ctx=ctx)

        assert result["status"] == "configured"
        assert result["server_id"] == "new-2"
        mock_configure.assert_called_once_with("new-2", {"API_KEY": "my-secret-key"})

    @pytest.mark.asyncio
    async def test_elicitation_decline(self):
        entry = {
            "manifest": {
                "name": "API Server",
                "runtime": "uvx",
                "env": [{"name": "API_KEY", "required": True}],
            }
        }
        elicit_result = DeclinedElicitation()
        ctx = _make_ctx(elicit_result)

        with (
            patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, return_value=entry),
            patch.object(obot_client, "list_user_mcp_servers", new_callable=AsyncMock, return_value=[]),
        ):
            result = await obot_configure_catalog_entry(entry_id="entry-1", ctx=ctx)
        assert result["status"] == "cancelled"

    @pytest.mark.asyncio
    async def test_elicitation_cancel(self):
        entry = {
            "manifest": {
                "name": "API Server",
                "runtime": "uvx",
                "env": [{"name": "API_KEY", "required": True}],
            }
        }
        elicit_result = CancelledElicitation()
        ctx = _make_ctx(elicit_result)

        with (
            patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, return_value=entry),
            patch.object(obot_client, "list_user_mcp_servers", new_callable=AsyncMock, return_value=[]),
        ):
            result = await obot_configure_catalog_entry(entry_id="entry-1", ctx=ctx)
        assert result["status"] == "cancelled"

    @pytest.mark.asyncio
    async def test_hostname_url_flow(self):
        entry = {
            "manifest": {
                "name": "Remote Server",
                "runtime": "remote",
                "env": [],
                "remoteConfig": {"hostname": "*.example.com"},
            }
        }
        elicit_data = {"url": "https://my.example.com/api"}
        elicit_result = AcceptedElicitation(data=elicit_data)
        ctx = _make_ctx(elicit_result)
        created = {"id": "new-3"}

        with (
            patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, return_value=entry),
            patch.object(obot_client, "list_user_mcp_servers", new_callable=AsyncMock, return_value=[]),
            patch.object(obot_client, "create_user_mcp_server", new_callable=AsyncMock, return_value=created) as mock_create,
        ):
            result = await obot_configure_catalog_entry(entry_id="entry-1", ctx=ctx)

        assert result["status"] == "configured"
        mock_create.assert_called_once_with("entry-1", url="https://my.example.com/api")

    @pytest.mark.asyncio
    async def test_hostname_validation_failure(self):
        entry = {
            "manifest": {
                "name": "Remote Server",
                "runtime": "remote",
                "env": [],
                "remoteConfig": {"hostname": "*.example.com"},
            }
        }
        elicit_data = {"url": "https://evil.other.com/api"}
        elicit_result = AcceptedElicitation(data=elicit_data)
        ctx = _make_ctx(elicit_result)

        with (
            patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, return_value=entry),
            patch.object(obot_client, "list_user_mcp_servers", new_callable=AsyncMock, return_value=[]),
        ):
            result = await obot_configure_catalog_entry(entry_id="entry-1", ctx=ctx)

        assert result["status"] == "error"
        assert "does not match" in result["message"]

    @pytest.mark.asyncio
    async def test_api_error_on_create(self):
        entry = {
            "manifest": {
                "name": "Simple Server",
                "runtime": "uvx",
                "env": [],
            }
        }
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        error = httpx.HTTPStatusError("Server error", request=MagicMock(), response=mock_response)

        with (
            patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, return_value=entry),
            patch.object(obot_client, "list_user_mcp_servers", new_callable=AsyncMock, return_value=[]),
            patch.object(obot_client, "create_user_mcp_server", new_callable=AsyncMock, side_effect=error),
        ):
            result = await obot_configure_catalog_entry(entry_id="entry-1", ctx=_make_ctx())
        assert result["status"] == "error"
        assert "Failed to create server" in result["message"]

    @pytest.mark.asyncio
    async def test_timeout_on_fetch(self):
        error = httpx.TimeoutException("Connection timed out")
        with patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, side_effect=error):
            result = await obot_configure_catalog_entry(entry_id="entry-1", ctx=_make_ctx())
        assert result["status"] == "error"
        assert "Failed to fetch" in result["message"]

    @pytest.mark.asyncio
    async def test_existing_unconfigured_server_reused(self):
        entry = {
            "manifest": {
                "name": "API Server",
                "runtime": "uvx",
                "env": [{"name": "API_KEY", "required": True}],
            }
        }
        existing = {"id": "existing-1", "catalogEntryID": "entry-1", "configured": False}
        elicit_data = {"API_KEY": "key123"}
        elicit_result = AcceptedElicitation(data=elicit_data)
        ctx = _make_ctx(elicit_result)

        with (
            patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, return_value=entry),
            patch.object(obot_client, "list_user_mcp_servers", new_callable=AsyncMock, return_value=[existing]),
            patch.object(obot_client, "create_user_mcp_server", new_callable=AsyncMock) as mock_create,
            patch.object(obot_client, "configure_user_mcp_server", new_callable=AsyncMock, return_value={}),
        ):
            result = await obot_configure_catalog_entry(entry_id="entry-1", ctx=ctx)

        assert result["status"] == "configured"
        assert result["server_id"] == "existing-1"
        mock_create.assert_not_called()

    @pytest.mark.asyncio
    async def test_url_update_for_existing_server(self):
        entry = {
            "manifest": {
                "name": "Remote Server",
                "runtime": "remote",
                "env": [],
                "remoteConfig": {"hostname": "*.example.com"},
            }
        }
        existing = {"id": "existing-1", "catalogEntryID": "entry-1", "configured": False}
        elicit_data = {"url": "https://my.example.com/api"}
        elicit_result = AcceptedElicitation(data=elicit_data)
        ctx = _make_ctx(elicit_result)

        with (
            patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, return_value=entry),
            patch.object(obot_client, "list_user_mcp_servers", new_callable=AsyncMock, return_value=[existing]),
            patch.object(obot_client, "update_user_mcp_server_url", new_callable=AsyncMock, return_value={}) as mock_update_url,
        ):
            result = await obot_configure_catalog_entry(entry_id="entry-1", ctx=ctx)

        assert result["status"] == "configured"
        mock_update_url.assert_called_once_with("existing-1", "https://my.example.com/api")


# --- Test ObotClient new methods ---


class TestObotClientNewMethods:
    def _make_client_with_mock(self):
        """Create an ObotClient with a mocked _client."""
        client = ObotClient(base_url="http://test", token="tok")
        mock_http = MagicMock()
        client._client = mock_http
        return client, mock_http

    @pytest.mark.asyncio
    async def test_list_user_mcp_servers(self):
        mock_response = MagicMock()
        mock_response.json.return_value = {"items": [{"id": "s1"}, {"id": "s2"}]}
        mock_response.raise_for_status = MagicMock()

        client, mock_http = self._make_client_with_mock()
        mock_http.get = AsyncMock(return_value=mock_response)
        result = await client.list_user_mcp_servers()

        assert len(result) == 2
        mock_http.get.assert_called_once_with("/api/mcp-servers")

    @pytest.mark.asyncio
    async def test_create_user_mcp_server_without_url(self):
        mock_response = MagicMock()
        mock_response.json.return_value = {"id": "new-1"}
        mock_response.raise_for_status = MagicMock()

        client, mock_http = self._make_client_with_mock()
        mock_http.post = AsyncMock(return_value=mock_response)
        result = await client.create_user_mcp_server("entry-1")

        assert result["id"] == "new-1"
        mock_http.post.assert_called_once_with(
            "/api/mcp-servers", json={"catalogEntryID": "entry-1"}
        )

    @pytest.mark.asyncio
    async def test_create_user_mcp_server_with_url(self):
        mock_response = MagicMock()
        mock_response.json.return_value = {"id": "new-1"}
        mock_response.raise_for_status = MagicMock()

        client, mock_http = self._make_client_with_mock()
        mock_http.post = AsyncMock(return_value=mock_response)
        result = await client.create_user_mcp_server("entry-1", url="https://my.example.com")

        mock_http.post.assert_called_once_with(
            "/api/mcp-servers",
            json={
                "catalogEntryID": "entry-1",
                "manifest": {"remoteConfig": {"url": "https://my.example.com"}},
            },
        )

    @pytest.mark.asyncio
    async def test_configure_user_mcp_server(self):
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "ok"}
        mock_response.raise_for_status = MagicMock()

        client, mock_http = self._make_client_with_mock()
        mock_http.post = AsyncMock(return_value=mock_response)
        result = await client.configure_user_mcp_server("s1", {"API_KEY": "val"})

        mock_http.post.assert_called_once_with(
            "/api/mcp-servers/s1/configure", json={"API_KEY": "val"}
        )

    @pytest.mark.asyncio
    async def test_update_user_mcp_server_url(self):
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "ok"}
        mock_response.raise_for_status = MagicMock()

        client, mock_http = self._make_client_with_mock()
        mock_http.post = AsyncMock(return_value=mock_response)
        result = await client.update_user_mcp_server_url("s1", "https://example.com")

        mock_http.post.assert_called_once_with(
            "/api/mcp-servers/s1/update-url", json={"url": "https://example.com"}
        )
