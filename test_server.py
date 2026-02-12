"""Tests for obot_configure_catalog_entry tool and related functions."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
from fastmcp.server.context import AcceptedElicitation, DeclinedElicitation, CancelledElicitation
from mcp.types import ElicitResult

from obot_mcp.server import (
    _extract_configuration_requirements,
    _validate_hostname,
    _build_elicitation_model,
    _find_existing_user_server,
    obot_configure_catalog_entry as obot_configure_catalog_entry_tool,
    get_mcp_server_connection_impl,
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


def _make_ctx(elicit_result=None, elicit_url_result=None):
    """Create a mock Context for testing."""
    ctx = AsyncMock(spec=["elicit", "session", "request_id"])
    if elicit_result is not None:
        ctx.elicit = AsyncMock(return_value=elicit_result)
    if elicit_url_result is not None:
        ctx.session = AsyncMock()
        ctx.session.send_request = AsyncMock(return_value=elicit_url_result)
    ctx.request_id = "test-request-id"
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
            patch.object(obot_client, "get_mcp_server_oauth_url", new_callable=AsyncMock, return_value=None),
        ):
            result = await obot_configure_catalog_entry(entry_id="entry-1", ctx=ctx)
        assert result["status"] == "already_configured"
        assert result["server_id"] == "s1"

    @pytest.mark.asyncio
    async def test_already_configured_with_oauth(self):
        """Test that OAuth is checked even for already configured servers."""
        entry = {"manifest": {"name": "OAuth Server", "runtime": "uvx", "env": []}}
        existing = {"id": "s1", "catalogEntryID": "entry-1", "configured": True}
        oauth_url = "https://oauth.example.com/authorize"

        # Mock OAuth acceptance
        ctx = _make_ctx(elicit_url_result=ElicitResult(action="accept"))

        with (
            patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, return_value=entry),
            patch.object(obot_client, "list_user_mcp_servers", new_callable=AsyncMock, return_value=[existing]),
            patch.object(obot_client, "get_mcp_server_oauth_url", new_callable=AsyncMock, side_effect=[oauth_url, None]),
            patch("obot_mcp.server.asyncio.sleep", new_callable=AsyncMock),
        ):
            result = await obot_configure_catalog_entry(entry_id="entry-1", ctx=ctx)

        assert result["status"] == "already_configured"
        assert result["server_id"] == "s1"
        # Verify OAuth elicitation was called
        ctx.session.send_request.assert_called_once()

    @pytest.mark.asyncio
    async def test_already_configured_with_oauth_declined(self):
        """Test that OAuth decline is handled for already configured servers."""
        entry = {"manifest": {"name": "OAuth Server", "runtime": "uvx", "env": []}}
        existing = {"id": "s1", "catalogEntryID": "entry-1", "configured": True}
        oauth_url = "https://oauth.example.com/authorize"

        # Mock OAuth decline
        ctx = _make_ctx(elicit_url_result=ElicitResult(action="decline"))

        with (
            patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, return_value=entry),
            patch.object(obot_client, "list_user_mcp_servers", new_callable=AsyncMock, return_value=[existing]),
            patch.object(obot_client, "get_mcp_server_oauth_url", new_callable=AsyncMock, return_value=oauth_url),
        ):
            result = await obot_configure_catalog_entry(entry_id="entry-1", ctx=ctx)

        assert result["status"] == "cancelled"
        assert "OAuth authentication was cancelled" in result["message"]

    @pytest.mark.asyncio
    async def test_no_config_needed_auto_create(self):
        ctx = _make_ctx()
        entry = {"manifest": {"name": "Simple Server", "runtime": "uvx", "env": []}}
        created = {"id": "new-1"}
        with (
            patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, return_value=entry),
            patch.object(obot_client, "list_user_mcp_servers", new_callable=AsyncMock, return_value=[]),
            patch.object(obot_client, "create_user_mcp_server", new_callable=AsyncMock, return_value=created),
            patch.object(obot_client, "get_mcp_server_oauth_url", new_callable=AsyncMock, return_value=None),
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
            patch.object(obot_client, "get_mcp_server_oauth_url", new_callable=AsyncMock, return_value=None),
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
            patch.object(obot_client, "get_mcp_server_oauth_url", new_callable=AsyncMock, return_value=None),
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
            patch.object(obot_client, "get_mcp_server_oauth_url", new_callable=AsyncMock, return_value=None),
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
            patch.object(obot_client, "get_mcp_server_oauth_url", new_callable=AsyncMock, return_value=None),
        ):
            result = await obot_configure_catalog_entry(entry_id="entry-1", ctx=ctx)

        assert result["status"] == "configured"
        mock_update_url.assert_called_once_with("existing-1", "https://my.example.com/api")


# --- Test ObotClient new methods ---


class TestObotClientNewMethods:
    def _make_client_with_mock(self):
        """Create an ObotClient with a mocked _client."""
        client = ObotClient(base_url="http://test")
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
        mock_http.get.assert_called_once_with(
            "/api/mcp-servers", headers={}
        )

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
            "/api/mcp-servers",
            json={"catalogEntryID": "entry-1"},
            headers={},
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
            headers={},
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
            "/api/mcp-servers/s1/configure",
            json={"API_KEY": "val"},
            headers={},
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
            "/api/mcp-servers/s1/update-url",
            json={"url": "https://example.com"},
            headers={},
        )

    @pytest.mark.asyncio
    async def test_get_mcp_server_oauth_url_required(self):
        """Test OAuth URL retrieval when OAuth is required."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"oauthURL": "https://oauth.example.com/authorize"}
        mock_response.raise_for_status = MagicMock()

        client, mock_http = self._make_client_with_mock()
        mock_http.get = AsyncMock(return_value=mock_response)
        result = await client.get_mcp_server_oauth_url("s1")

        assert result == "https://oauth.example.com/authorize"
        mock_http.get.assert_called_once_with(
            "/api/mcp-servers/s1/oauth-url",
            headers={},
        )

    @pytest.mark.asyncio
    async def test_get_mcp_server_oauth_url_not_required(self):
        """Test OAuth URL retrieval when OAuth is not required."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"oauthURL": ""}
        mock_response.raise_for_status = MagicMock()

        client, mock_http = self._make_client_with_mock()
        mock_http.get = AsyncMock(return_value=mock_response)
        result = await client.get_mcp_server_oauth_url("s1")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_mcp_server_oauth_url_server_not_found(self):
        """Test OAuth URL retrieval when server doesn't exist yet."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        error = httpx.HTTPStatusError("Not found", request=MagicMock(), response=mock_response)

        client, mock_http = self._make_client_with_mock()
        mock_http.get = AsyncMock(side_effect=error)
        result = await client.get_mcp_server_oauth_url("s1")

        assert result is None


# --- Test OAuth Configuration Flow ---


class TestOAuthConfigurationFlow:
    @pytest.mark.asyncio
    async def test_configure_with_oauth_required_accepted(self):
        """Test configuration flow with OAuth requirement - user accepts."""
        entry = {"manifest": {"name": "OAuth Server", "runtime": "uvx", "env": []}}
        created = {"id": "oauth-1"}
        oauth_url = "https://oauth.example.com/authorize"

        # Mock OAuth acceptance
        ctx = _make_ctx(elicit_url_result=ElicitResult(action="accept"))

        with (
            patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, return_value=entry),
            patch.object(obot_client, "list_user_mcp_servers", new_callable=AsyncMock, return_value=[]),
            patch.object(obot_client, "create_user_mcp_server", new_callable=AsyncMock, return_value=created),
            patch.object(obot_client, "get_mcp_server_oauth_url", new_callable=AsyncMock, side_effect=[oauth_url, None]),
            patch("obot_mcp.server.asyncio.sleep", new_callable=AsyncMock),
        ):
            result = await obot_configure_catalog_entry(entry_id="entry-1", ctx=ctx)

        assert result["status"] == "configured"
        assert result["server_id"] == "oauth-1"
        # Verify OAuth elicitation was called
        ctx.session.send_request.assert_called_once()

    @pytest.mark.asyncio
    async def test_configure_with_oauth_required_declined(self):
        """Test configuration flow with OAuth requirement - user declines."""
        entry = {"manifest": {"name": "OAuth Server", "runtime": "uvx", "env": []}}
        created = {"id": "oauth-1"}
        oauth_url = "https://oauth.example.com/authorize"

        # Mock OAuth decline
        ctx = _make_ctx(elicit_url_result=ElicitResult(action="decline"))

        with (
            patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, return_value=entry),
            patch.object(obot_client, "list_user_mcp_servers", new_callable=AsyncMock, return_value=[]),
            patch.object(obot_client, "create_user_mcp_server", new_callable=AsyncMock, return_value=created),
            patch.object(obot_client, "get_mcp_server_oauth_url", new_callable=AsyncMock, return_value=oauth_url),
        ):
            result = await obot_configure_catalog_entry(entry_id="entry-1", ctx=ctx)

        assert result["status"] == "cancelled"
        assert "OAuth authentication was cancelled" in result["message"]

    @pytest.mark.asyncio
    async def test_configure_with_oauth_and_config_required(self):
        """Test configuration flow with both OAuth and config parameters."""
        entry = {
            "manifest": {
                "name": "OAuth API Server",
                "runtime": "uvx",
                "env": [{"name": "API_KEY", "description": "Key", "required": True}],
            }
        }
        created = {"id": "oauth-2"}
        oauth_url = "https://oauth.example.com/authorize"

        # Config elicitation goes through ctx.elicit, OAuth goes through ctx.session.elicit_url
        ctx = _make_ctx(
            elicit_result=AcceptedElicitation(data={"API_KEY": "my-secret-key"}),
            elicit_url_result=ElicitResult(action="accept"),
        )

        with (
            patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, return_value=entry),
            patch.object(obot_client, "list_user_mcp_servers", new_callable=AsyncMock, return_value=[]),
            patch.object(obot_client, "create_user_mcp_server", new_callable=AsyncMock, return_value=created),
            patch.object(obot_client, "get_mcp_server_oauth_url", new_callable=AsyncMock, side_effect=[oauth_url, None]),
            patch.object(obot_client, "configure_user_mcp_server", new_callable=AsyncMock, return_value={}) as mock_configure,
            patch("obot_mcp.server.asyncio.sleep", new_callable=AsyncMock),
        ):
            result = await obot_configure_catalog_entry(entry_id="entry-1", ctx=ctx)

        assert result["status"] == "configured"
        assert result["server_id"] == "oauth-2"
        # Verify both elicitations happened (config form + OAuth URL)
        ctx.elicit.assert_called_once()
        ctx.session.send_request.assert_called_once()
        mock_configure.assert_called_once_with("oauth-2", {"API_KEY": "my-secret-key"})


# --- Test get_mcp_server_connection_impl with OAuth ---


class TestGetMcpServerConnection:
    @pytest.mark.asyncio
    async def test_catalog_entry_without_oauth(self):
        """Test catalog entry connection without OAuth requirement."""
        catalog_entry = {
            "manifest": {
                "name": "Simple Server",
                "runtime": "uvx",
                "env": [],
            }
        }
        created_server = {"id": "user-server-1"}
        ctx = _make_ctx()

        with (
            patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, return_value=catalog_entry),
            patch.object(obot_client, "list_user_mcp_servers", new_callable=AsyncMock, return_value=[]),
            patch.object(obot_client, "create_user_mcp_server", new_callable=AsyncMock, return_value=created_server),
            patch.object(obot_client, "get_mcp_server_oauth_url", new_callable=AsyncMock, return_value=None),
            patch.object(obot_client, "get_multi_user_server", new_callable=AsyncMock, return_value=None),
        ):
            result = await get_mcp_server_connection_impl("catalog-1", ctx)

        assert result["status"] == "available"
        assert result["connect_url"] == "http://localhost:8080/mcp-connect/user-server-1"

    @pytest.mark.asyncio
    async def test_catalog_entry_with_oauth_accepted(self):
        """Test catalog entry with OAuth - user accepts and token is polled."""
        catalog_entry = {
            "manifest": {
                "name": "OAuth Server",
                "runtime": "uvx",
                "env": [],
            }
        }
        created_server = {"id": "user-server-2"}
        oauth_url = "https://oauth.example.com/authorize"

        ctx = _make_ctx(elicit_url_result=ElicitResult(action="accept"))

        with (
            patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, return_value=catalog_entry),
            patch.object(obot_client, "list_user_mcp_servers", new_callable=AsyncMock, return_value=[]),
            patch.object(obot_client, "create_user_mcp_server", new_callable=AsyncMock, return_value=created_server),
            patch.object(obot_client, "get_mcp_server_oauth_url", new_callable=AsyncMock, side_effect=[oauth_url, None]),
            patch.object(obot_client, "get_multi_user_server", new_callable=AsyncMock, return_value=None),
            patch("obot_mcp.server.asyncio.sleep", new_callable=AsyncMock),
        ):
            result = await get_mcp_server_connection_impl("catalog-1", ctx)

        assert result["status"] == "available"
        assert result["connect_url"] == "http://localhost:8080/mcp-connect/user-server-2"
        ctx.session.send_request.assert_called_once()

    @pytest.mark.asyncio
    async def test_catalog_entry_with_oauth_declined(self):
        """Test catalog entry with OAuth - user declines."""
        catalog_entry = {
            "manifest": {
                "name": "OAuth Server",
                "runtime": "uvx",
                "env": [],
            }
        }
        created_server = {"id": "user-server-2"}
        oauth_url = "https://oauth.example.com/authorize"

        ctx = _make_ctx(elicit_url_result=ElicitResult(action="decline"))

        with (
            patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, return_value=catalog_entry),
            patch.object(obot_client, "list_user_mcp_servers", new_callable=AsyncMock, return_value=[]),
            patch.object(obot_client, "create_user_mcp_server", new_callable=AsyncMock, return_value=created_server),
            patch.object(obot_client, "get_mcp_server_oauth_url", new_callable=AsyncMock, return_value=oauth_url),
            patch.object(obot_client, "get_multi_user_server", new_callable=AsyncMock, return_value=None),
        ):
            result = await get_mcp_server_connection_impl("catalog-1", ctx)

        assert result["status"] == "cancelled"
        assert "OAuth authentication was cancelled" in result["message"]

    @pytest.mark.asyncio
    async def test_catalog_entry_with_existing_server_and_oauth(self):
        """Test catalog entry with existing user server and OAuth requirement."""
        catalog_entry = {
            "manifest": {
                "name": "OAuth Server",
                "runtime": "uvx",
                "env": [],
            }
        }
        existing_server = {"id": "existing-server-1", "catalogEntryID": "catalog-1"}
        oauth_url = "https://oauth.example.com/authorize"

        ctx = _make_ctx(elicit_url_result=ElicitResult(action="accept"))

        with (
            patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, return_value=catalog_entry),
            patch.object(obot_client, "list_user_mcp_servers", new_callable=AsyncMock, return_value=[existing_server]),
            patch.object(obot_client, "create_user_mcp_server", new_callable=AsyncMock) as mock_create,
            patch.object(obot_client, "get_mcp_server_oauth_url", new_callable=AsyncMock, side_effect=[oauth_url, None]),
            patch.object(obot_client, "get_multi_user_server", new_callable=AsyncMock, return_value=None),
            patch("obot_mcp.server.asyncio.sleep", new_callable=AsyncMock),
        ):
            result = await get_mcp_server_connection_impl("catalog-1", ctx)

        assert result["status"] == "available"
        assert result["connect_url"] == "http://localhost:8080/mcp-connect/existing-server-1"
        # Should not create new server if one exists
        mock_create.assert_not_called()
        ctx.session.send_request.assert_called_once()

    @pytest.mark.asyncio
    async def test_multi_user_server_without_oauth(self):
        """Test multi-user server connection without OAuth requirement."""
        multi_user_server = {
            "id": "multi-server-1",
            "configured": True,
            "needsURL": False,
            "manifest": {
                "name": "Multi Server",
                "runtime": "containerized",
            }
        }
        ctx = _make_ctx()

        with (
            patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, return_value=None),
            patch.object(obot_client, "get_multi_user_server", new_callable=AsyncMock, return_value=multi_user_server),
            patch.object(obot_client, "get_mcp_server_oauth_url", new_callable=AsyncMock, return_value=None),
        ):
            result = await get_mcp_server_connection_impl("multi-server-1", ctx)

        assert result["status"] == "available"
        assert result["connect_url"] == "http://localhost:8080/mcp-connect/multi-server-1"

    @pytest.mark.asyncio
    async def test_multi_user_server_with_oauth_accepted(self):
        """Test multi-user server with OAuth - user accepts and token is polled."""
        multi_user_server = {
            "id": "multi-server-2",
            "configured": True,
            "needsURL": False,
            "manifest": {
                "name": "OAuth Multi Server",
                "runtime": "containerized",
            }
        }
        oauth_url = "https://oauth.example.com/authorize"

        ctx = _make_ctx(elicit_url_result=ElicitResult(action="accept"))

        with (
            patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, return_value=None),
            patch.object(obot_client, "get_multi_user_server", new_callable=AsyncMock, return_value=multi_user_server),
            patch.object(obot_client, "get_mcp_server_oauth_url", new_callable=AsyncMock, side_effect=[oauth_url, None]),
            patch("obot_mcp.server.asyncio.sleep", new_callable=AsyncMock),
        ):
            result = await get_mcp_server_connection_impl("multi-server-2", ctx)

        assert result["status"] == "available"
        assert result["connect_url"] == "http://localhost:8080/mcp-connect/multi-server-2"
        ctx.session.send_request.assert_called_once()

    @pytest.mark.asyncio
    async def test_multi_user_server_with_oauth_declined(self):
        """Test multi-user server with OAuth - user declines."""
        multi_user_server = {
            "id": "multi-server-2",
            "configured": True,
            "needsURL": False,
            "manifest": {
                "name": "OAuth Multi Server",
                "runtime": "containerized",
            }
        }
        oauth_url = "https://oauth.example.com/authorize"

        ctx = _make_ctx(elicit_url_result=ElicitResult(action="decline"))

        with (
            patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, return_value=None),
            patch.object(obot_client, "get_multi_user_server", new_callable=AsyncMock, return_value=multi_user_server),
            patch.object(obot_client, "get_mcp_server_oauth_url", new_callable=AsyncMock, return_value=oauth_url),
        ):
            result = await get_mcp_server_connection_impl("multi-server-2", ctx)

        assert result["status"] == "cancelled"
        assert "OAuth authentication was cancelled" in result["message"]

    @pytest.mark.asyncio
    async def test_server_not_found(self):
        """Test when server is not found."""
        ctx = _make_ctx()

        with (
            patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, return_value=None),
            patch.object(obot_client, "get_multi_user_server", new_callable=AsyncMock, return_value=None),
        ):
            result = await get_mcp_server_connection_impl("nonexistent", ctx)

        assert result["status"] == "not_found"
        assert "No server or catalog entry found" in result["message"]

    @pytest.mark.asyncio
    async def test_catalog_entry_requires_configuration(self):
        """Test catalog entry that requires configuration."""
        catalog_entry = {
            "manifest": {
                "name": "Config Server",
                "runtime": "uvx",
                "env": [
                    {"name": "API_KEY", "description": "API Key", "required": True}
                ],
            }
        }
        ctx = _make_ctx()

        with (
            patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, return_value=catalog_entry),
            patch.object(obot_client, "get_multi_user_server", new_callable=AsyncMock, return_value=None),
        ):
            result = await get_mcp_server_connection_impl("catalog-1", ctx)

        assert result["status"] == "requires_configuration"
        assert "configure_url" in result
        assert "environment variables" in result["message"]

    @pytest.mark.asyncio
    async def test_multi_user_server_needs_configuration(self):
        """Test multi-user server that needs configuration."""
        multi_user_server = {
            "id": "multi-server-4",
            "configured": False,
            "needsURL": False,
            "manifest": {
                "name": "Unconfigured Server",
                "runtime": "uvx",
            }
        }
        ctx = _make_ctx()

        with (
            patch.object(obot_client, "get_catalog_entry", new_callable=AsyncMock, return_value=None),
            patch.object(obot_client, "get_multi_user_server", new_callable=AsyncMock, return_value=multi_user_server),
        ):
            result = await get_mcp_server_connection_impl("multi-server-4", ctx)

        assert result["status"] == "requires_configuration"
        assert "configure_url" in result
