"""Tests for HIBP OSINT connector."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from sisifo.osint import get_connector, list_connectors
from sisifo.osint.contract import QueryType
from sisifo.osint.executor import OsintExecutionError
from sisifo.osint.hibp import HibpConnector


def test_hibp_connector_registered():
    """Test that HIBP connector is registered."""
    connectors = list_connectors()
    assert "hibp" in connectors
    meta = connectors["hibp"]
    assert meta["id"] == "hibp"
    assert meta["name"] == "Have I Been Pwned"
    assert QueryType.EMAIL.value in meta["query_types"]
    assert "breach_lookup" in meta["capabilities"]


def test_hibp_connector_instantiation():
    """Test HIBP connector can be instantiated."""
    conn = get_connector("hibp")
    assert isinstance(conn, HibpConnector)
    assert conn.meta.id == "hibp"


def test_hibp_validate_config():
    """Test configuration validation.

    HIBP API key is 32 hex characters, no prefix.
    """
    conn = HibpConnector()

    # Valid config - 32 hex chars
    valid_key = "a" * 32
    assert conn.validate_config({"api_key": valid_key}) is True

    # Valid config - uppercase hex
    valid_key_upper = "A" * 32
    assert conn.validate_config({"api_key": valid_key_upper}) is True

    # Valid config - mixed case
    valid_key_mixed = "aBcDeF" + "0" * 26
    assert conn.validate_config({"api_key": valid_key_mixed}) is True

    # Invalid configs
    assert conn.validate_config({}) is False
    assert conn.validate_config({"api_key": ""}) is False
    assert conn.validate_config({"api_key": "hibp-test-key"}) is False  # old prefix format
    assert conn.validate_config({"api_key": "x" * 31}) is False  # too short
    assert conn.validate_config({"api_key": "x" * 33}) is False  # too long
    assert conn.validate_config({"api_key": "g" * 32}) is False  # non-hex char
    assert conn.validate_config({"api_key": 123}) is False
    assert conn.validate_config({"api_key": " " * 32}) is False  # whitespace


def test_hibp_diagnose():
    """Test diagnosis."""
    conn = HibpConnector()

    # Invalid config
    result = conn.diagnose({})
    assert result["ok"] is False
    assert "api_key" in result["reason"].lower()
    assert result["will_call_external"] is False

    # Valid config format
    result = conn.diagnose({"api_key": "a" * 32})
    assert result["ok"] is True
    assert result["will_call_external"] is False


def test_hibp_validate_query():
    """Test query validation for EMAIL type."""
    conn = HibpConnector()

    # Valid emails
    assert conn.validate_query("test@example.com", QueryType.EMAIL) is True
    assert conn.validate_query("user.name@domain.org", QueryType.EMAIL) is True
    assert conn.validate_query("user+tag@example.co.uk", QueryType.EMAIL) is True
    assert conn.validate_query("a@b.co", QueryType.EMAIL) is True

    # Invalid emails
    assert conn.validate_query("invalid-email", QueryType.EMAIL) is False  # no @
    assert conn.validate_query("@nodomain.com", QueryType.EMAIL) is False  # empty local
    assert conn.validate_query("user@", QueryType.EMAIL) is False  # empty domain
    assert conn.validate_query("user@.com", QueryType.EMAIL) is False  # invalid domain
    assert conn.validate_query("user name@domain.com", QueryType.EMAIL) is False  # space in local
    assert conn.validate_query("a" * 65 + "@example.com", QueryType.EMAIL) is False  # local too long
    assert conn.validate_query("test@" + "x" * 255, QueryType.EMAIL) is False  # domain too long
    assert conn.validate_query("test\x00@example.com", QueryType.EMAIL) is False  # control char

    # Wrong query type
    assert conn.validate_query("test@example.com", QueryType.DOMAIN) is False
    assert conn.validate_query("test@example.com", QueryType.IP) is False
    assert conn.validate_query("test@example.com", QueryType.URL) is False
    assert conn.validate_query("test@example.com", QueryType.HASH) is False


@pytest.mark.asyncio
async def test_hibp_query_with_transport_success():
    """Test successful query execution with mocked transport."""
    conn = HibpConnector()
    config = {"api_key": "a" * 32}

    # Mock transport
    transport = AsyncMock()
    mock_response = MagicMock()
    mock_response.json.return_value = [
        {
            "Name": "Adobe",
            "Title": "Adobe",
            "Domain": "adobe.com",
            "BreachDate": "2013-10-04",
            "AddedDate": "2013-12-04T00:00:00Z",
            "ModifiedDate": "2013-12-04T00:00:00Z",
            "PwnCount": 152445165,
            "Description": "In October 2013, Adobe suffered a data breach...",
            "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/Adobe.png",
            "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"],
            "IsVerified": True,
            "IsFabricated": False,
            "IsSensitive": False,
            "IsRetired": False,
            "IsSpamList": False,
            "IsMalware": False,
            "IsStealerLog": False,
            "Attribution": None,
        }
    ]
    transport.execute_http_query = AsyncMock(return_value=mock_response)

    results = await conn.query_with_transport("test@example.com", QueryType.EMAIL, config, transport)

    assert len(results) == 1
    assert results[0]["Name"] == "Adobe"
    transport.execute_http_query.assert_called_once()


@pytest.mark.asyncio
async def test_hibp_query_with_transport_no_breaches():
    """Test query when no breaches found (404 on breachedaccount).

    Per HIBP docs, 404 on breachedaccount means no breaches found.
    The connector maps this to NO_BREACHES_FOUND error.
    """
    conn = HibpConnector()
    config = {"api_key": "a" * 32}

    transport = AsyncMock()
    transport.execute_http_query = AsyncMock(
        side_effect=OsintExecutionError("Serviço retornou HTTP 404", code="HTTP_ERROR", details={"status_code": 404})
    )

    assert await conn.query_with_transport("clean@example.com", QueryType.EMAIL, config, transport) == []


@pytest.mark.asyncio
async def test_hibp_query_with_transport_auth_error():
    """Test query with authentication error (401)."""
    conn = HibpConnector()
    config = {"api_key": "a" * 32}

    transport = AsyncMock()
    transport.execute_http_query = AsyncMock(
        side_effect=OsintExecutionError("Serviço retornou HTTP 401", code="HTTP_ERROR", details={"status_code": 401})
    )

    with pytest.raises(OsintExecutionError) as exc_info:
        await conn.query_with_transport("test@example.com", QueryType.EMAIL, config, transport)

    assert exc_info.value.code == "AUTHENTICATION_FAILED"


@pytest.mark.asyncio
async def test_hibp_query_with_transport_forbidden():
    """Test query with forbidden error (403)."""
    conn = HibpConnector()
    config = {"api_key": "a" * 32}

    transport = AsyncMock()
    transport.execute_http_query = AsyncMock(
        side_effect=OsintExecutionError("Serviço retornou HTTP 403", code="HTTP_ERROR", details={"status_code": 403})
    )

    with pytest.raises(OsintExecutionError) as exc_info:
        await conn.query_with_transport("test@example.com", QueryType.EMAIL, config, transport)

    assert exc_info.value.code == "ACCESS_FORBIDDEN"


@pytest.mark.asyncio
async def test_hibp_query_with_transport_rate_limit():
    """Test query with rate limit error (429)."""
    conn = HibpConnector()
    config = {"api_key": "a" * 32}

    transport = AsyncMock()
    transport.execute_http_query = AsyncMock(
        side_effect=OsintExecutionError("Serviço retornou HTTP 429", code="HTTP_ERROR", details={"status_code": 429})
    )

    with pytest.raises(OsintExecutionError) as exc_info:
        await conn.query_with_transport("test@example.com", QueryType.EMAIL, config, transport)

    assert exc_info.value.code == "RATE_LIMIT_EXCEEDED"


@pytest.mark.asyncio
async def test_hibp_query_with_transport_not_found_other_endpoint():
    """Test 404 on other endpoints raises NOT_FOUND."""
    conn = HibpConnector()
    error = OsintExecutionError("Mensagem sem status", code="HTTP_ERROR", details={"status_code": 404})
    assert conn._map_hibp_error(error, "breach").code == "NOT_FOUND"


def test_hibp_normalize():
    """Test normalization of raw HIBP response."""
    conn = HibpConnector()

    raw = [
        {
            "Name": "Adobe",
            "Title": "Adobe",
            "Domain": "adobe.com",
            "BreachDate": "2013-10-04",
            "AddedDate": "2013-12-04T00:00:00Z",
            "ModifiedDate": "2013-12-04T00:00:00Z",
            "PwnCount": 152445165,
            "Description": "In October 2013...",
            "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/Adobe.png",
            "DataClasses": ["Email addresses", "Passwords"],
            "IsVerified": True,
            "IsFabricated": False,
            "IsSensitive": False,
            "IsRetired": False,
            "IsSpamList": False,
            "IsMalware": False,
            "IsStealerLog": False,
            "Attribution": None,
        },
        {
            "Name": "LinkedIn",
            "Title": "LinkedIn",
            "Domain": "linkedin.com",
            "BreachDate": "2012-05-05",
            "AddedDate": "2016-05-19T00:00:00Z",
            "ModifiedDate": "2016-05-19T00:00:00Z",
            "PwnCount": 164611595,
            "Description": "In May 2012...",
            "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/LinkedIn.png",
            "DataClasses": ["Email addresses", "Passwords"],
            "IsVerified": True,
            "IsFabricated": False,
            "IsSensitive": False,
            "IsRetired": False,
            "IsSpamList": False,
            "IsMalware": False,
            "IsStealerLog": False,
            "Attribution": None,
        }
    ]

    results = conn.normalize(raw, original_query="test@example.com")

    assert len(results) == 2

    # Check first result
    r1 = results[0]
    assert r1.source == "hibp"
    assert r1.query == "test@example.com"
    assert r1.query_type == QueryType.EMAIL
    assert r1.evidence["hibp_breach_name"] == "Adobe"
    assert r1.evidence["hibp_domain"] == "adobe.com"
    assert r1.evidence["hibp_pwn_count"] == 152445165
    assert r1.evidence["hibp_data_classes"] == ["Email addresses", "Passwords"]
    assert r1.evidence["hibp_is_verified"] is True
    assert r1.reference_url == "https://haveibeenpwned.com/PwnedWebsites#Adobe"
    assert "Dados baseados no banco do HIBP" in r1.limitations[0]
    assert "termos de uso do HIBP" in r1.limitations[2]

    # Check second result
    r2 = results[1]
    assert r2.source == "hibp"
    assert r2.query == "test@example.com"
    assert r2.evidence["hibp_breach_name"] == "LinkedIn"


def test_hibp_normalize_with_warnings():
    """Test normalization includes warnings for sensitive/fabricated/retired/malware/stealer."""
    conn = HibpConnector()

    raw = [
        {
            "Name": "SensitiveBreach",
            "Title": "Sensitive Breach",
            "Domain": "sensitive.com",
            "BreachDate": "2020-01-01",
            "AddedDate": "2020-01-02T00:00:00Z",
            "PwnCount": 1000,
            "Description": "Sensitive breach",
            "DataClasses": ["Email addresses"],
            "IsVerified": True,
            "IsFabricated": False,
            "IsSensitive": True,
            "IsRetired": False,
            "IsSpamList": False,
            "IsMalware": False,
            "IsStealerLog": False,
            "Attribution": None,
        },
        {
            "Name": "FabricatedBreach",
            "Title": "Fabricated Breach",
            "Domain": "fabricated.com",
            "BreachDate": "2020-01-01",
            "AddedDate": "2020-01-02T00:00:00Z",
            "PwnCount": 1000,
            "Description": "Fabricated breach",
            "DataClasses": ["Email addresses"],
            "IsVerified": True,
            "IsFabricated": True,
            "IsSensitive": False,
            "IsRetired": False,
            "IsSpamList": False,
            "IsMalware": False,
            "IsStealerLog": False,
            "Attribution": None,
        },
        {
            "Name": "RetiredBreach",
            "Title": "Retired Breach",
            "Domain": "retired.com",
            "BreachDate": "2020-01-01",
            "AddedDate": "2020-01-02T00:00:00Z",
            "PwnCount": 1000,
            "Description": "Retired breach",
            "DataClasses": ["Email addresses"],
            "IsVerified": True,
            "IsFabricated": False,
            "IsSensitive": False,
            "IsRetired": True,
            "IsSpamList": False,
            "IsMalware": False,
            "IsStealerLog": False,
            "Attribution": None,
        },
        {
            "Name": "MalwareBreach",
            "Title": "Malware Breach",
            "Domain": "malware.com",
            "BreachDate": "2020-01-01",
            "AddedDate": "2020-01-02T00:00:00Z",
            "PwnCount": 1000,
            "Description": "Malware breach",
            "DataClasses": ["Email addresses"],
            "IsVerified": True,
            "IsFabricated": False,
            "IsSensitive": False,
            "IsRetired": False,
            "IsSpamList": False,
            "IsMalware": True,
            "IsStealerLog": False,
            "Attribution": None,
        },
        {
            "Name": "StealerLogBreach",
            "Title": "Stealer Log Breach",
            "Domain": "stealer.com",
            "BreachDate": "2020-01-01",
            "AddedDate": "2020-01-02T00:00:00Z",
            "PwnCount": 1000,
            "Description": "Stealer log breach",
            "DataClasses": ["Email addresses", "Passwords"],
            "IsVerified": True,
            "IsFabricated": False,
            "IsSensitive": False,
            "IsRetired": False,
            "IsSpamList": False,
            "IsMalware": False,
            "IsStealerLog": True,
            "Attribution": "Unknown",
        }
    ]

    results = conn.normalize(raw)

    # Check sensitive warning
    assert any("sensível" in w.lower() for w in results[0].warnings)

    # Check fabricated warning
    assert any("fabricada" in w.lower() for w in results[1].warnings)

    # Check retired warning
    assert any("aposentada" in w.lower() for w in results[2].warnings)

    # Check malware warning
    assert any("malware" in w.lower() or "stealer" in w.lower() for w in results[3].warnings)

    # Check stealer log warning
    assert any("stealer" in w.lower() for w in results[4].warnings)


def test_hibp_normalize_invalid_input():
    """Test normalization handles invalid input by raising error."""
    conn = HibpConnector()

    # Not a list - should raise OsintExecutionError
    with pytest.raises(OsintExecutionError) as exc_info:
        conn.normalize({"not": "a list"})
    assert exc_info.value.code == "INVALID_RAW_DATA"

    # Malformed entries must not disappear as a successful empty result
    raw = ["not a dict", 123, {"Name": "Valid", "Title": "Valid", "Domain": "valid.com",
                                "BreachDate": "2020-01-01", "AddedDate": "2020-01-02T00:00:00Z",
                                "PwnCount": 100, "Description": "Valid", "DataClasses": ["Email"],
                                "IsVerified": True, "IsFabricated": False, "IsSensitive": False,
                                "IsRetired": False, "IsSpamList": False, "IsMalware": False}]
    with pytest.raises(OsintExecutionError, match="Item HIBP"):
        conn.normalize(raw, original_query="test@example.com")

    # Empty list
    results = conn.normalize([])
    assert results == []


def test_hibp_normalize_missing_name():
    """Incomplete response cannot be reported as complete evidence."""
    conn = HibpConnector()

    raw = [
        {"Title": "No Name", "Domain": "test.com"},  # Missing Name
        {"Name": "Valid", "Title": "Valid", "Domain": "valid.com",
         "BreachDate": "2020-01-01", "AddedDate": "2020-01-02T00:00:00Z",
         "PwnCount": 100, "Description": "Valid", "DataClasses": ["Email"],
         "IsVerified": True, "IsFabricated": False, "IsSensitive": False,
         "IsRetired": False, "IsSpamList": False, "IsMalware": False},
    ]
    with pytest.raises(OsintExecutionError, match="Nome"):
        conn.normalize(raw, original_query="test@example.com")


def test_hibp_build_headers():
    """Test header building."""
    conn = HibpConnector()
    headers = conn._build_headers("a" * 32)

    assert headers["hibp-api-key"] == "a" * 32
    assert headers["User-Agent"] == "Sisifo-OSINT/0.1"
    assert headers["Accept"] == "application/json"


@pytest.mark.asyncio
async def test_hibp_additional_methods():
    """Test additional capability methods (internal, not registered as capabilities)."""
    conn = HibpConnector()
    config = {"api_key": "a" * 32}
    transport = AsyncMock()

    # Mock response object
    mock_response = MagicMock()
    transport.execute_http_query = AsyncMock(return_value=mock_response)

    # list_breaches
    mock_response.json.return_value = [{"Name": "Test"}]
    result = await conn.list_breaches(config, transport)
    assert result == [{"Name": "Test"}]

    # get_breach_detail
    mock_response.json.return_value = {"Name": "Test", "Detail": "Full"}
    result = await conn.get_breach_detail("Test", config, transport)
    assert result == {"Name": "Test", "Detail": "Full"}

    # get_dataclasses
    mock_response.json.return_value = ["Email addresses", "Passwords"]
    result = await conn.get_dataclasses(config, transport)
    assert result == ["Email addresses", "Passwords"]


@pytest.mark.asyncio
async def test_hibp_query_cancellation():
    """Test that cancellation is propagated during query."""
    import asyncio

    from sisifo.core.execution import BudgetExceeded, Control

    conn = HibpConnector()
    config = {"api_key": "a" * 32}

    transport = AsyncMock()
    # Simulate a slow response
    async def slow_response(*args, **kwargs):
        await asyncio.sleep(10)
        return MagicMock()
    transport.execute_http_query = slow_response

    control = Control(seconds=1)  # 1 second timeout

    with pytest.raises(BudgetExceeded):
        await conn.query_with_transport("test@example.com", QueryType.EMAIL, config, transport, control)


@pytest.mark.asyncio
async def test_hibp_retry_after_cancellation():
    """Test that Retry-After wait can be cancelled."""

    from sisifo.core.execution import Control

    conn = HibpConnector()
    config = {"api_key": "a" * 32}

    transport = AsyncMock()
    call_count = 0

    async def rate_limited_then_success(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First call returns 429
            mock_resp = MagicMock()
            mock_resp.status_code = 429
            mock_resp.headers = {"Retry-After": "60"}
            mock_resp.aiter_bytes = AsyncMock(return_value=iter([b""]))
            raise OsintExecutionError("Serviço retornou HTTP 429", code="HTTP_ERROR", details={"status_code": 429})
        # Second call succeeds
        mock_resp = MagicMock()
        mock_resp.json.return_value = []
        mock_resp.status_code = 200
        return mock_resp

    transport.execute_http_query = rate_limited_then_success

    control = Control(seconds=1)  # Timeout before retry

    with pytest.raises(OsintExecutionError) as exc_info:
        await conn.query_with_transport("test@example.com", QueryType.EMAIL, config, transport, control)

    assert exc_info.value.code in ("CANCELLED", "QUERY_EXECUTION_FAILED", "RATE_LIMIT_EXCEEDED")

def test_breach_date_without_added_timestamp():
    result = HibpConnector().normalize([{'Name': 'Synthetic', 'BreachDate': '2024-01-01'}], 'test@example.com')[0]
    assert result.original_timestamp is None
    assert result.evidence['hibp_breach_date'] == '2024-01-01'
