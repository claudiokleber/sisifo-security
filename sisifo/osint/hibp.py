"""Have I Been Pwned (HIBP) OSINT Connector.

Official API: https://haveibeenpwned.com/API/v3
Documentation: https://haveibeenpwned.com/API/v3#breachedAccount
Terms of Use: https://haveibeenpwned.com/TermsOfUse
Consulted: 2026-10-09
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from sisifo.core.execution import BudgetExceeded, Cancelled
from sisifo.osint.contract import (
    BaseConnector,
    ConnectorConfig,
    ConnectorMeta,
    ConnectorResult,
    ConnectorStatus,
    CredentialField,
    QueryType,
)
from sisifo.osint.executor import OsintExecutionError, controlled


class HibpConnector(BaseConnector):
    ai_evidence_fields = frozenset(
        {
            "hibp_breach_name",
            "hibp_title",
            "hibp_domain",
            "hibp_breach_date",
            "hibp_data_classes",
            "hibp_is_verified",
            "hibp_is_sensitive",
            "hibp_is_fabricated",
            "hibp_is_retired",
            "hibp_is_malware",
            "hibp_is_stealer_log",
        }
    )
    """Have I Been Pwned connector for email breach lookup.

    The HIBP API v3 breachedaccount endpoint accepts an email address
    and returns a list of breaches where that email was found.
    """

    simulated = False
    meta = ConnectorMeta(
        id="hibp",
        name="Have I Been Pwned",
        description=(
            "Consulta exposição de endereços de e-mail em violações de dados "
            "conhecidas via API HIBP v3 (breachedaccount endpoint)."
        ),
        version="0.1.0",
        query_types=[QueryType.EMAIL],
        config=ConnectorConfig(
            fields=[
                CredentialField(
                    name="api_key",
                    description=(
                        "Chave de API HIBP (32 caracteres hexadecimais, "
                        "obtenha em https://haveibeenpwned.com/API/Key)"
                    ),
                    secret=True,
                ),
            ]
        ),
        allowed_destinations=["haveibeenpwned.com"],
        capabilities=["breach_lookup"],
        limits={
            "rate_per_minute": 30,  # Conservative local limit; independent of subscription
            "connect_timeout": 10.0,
            "read_timeout": 30.0,
            "write_timeout": 10.0,
            "pool_timeout": 5.0,
            "max_connections": 5,
            "max_keepalive": 2,
            "max_retries": 2,
            "max_response_size": 2 * 1024 * 1024,  # 2MB
        },
        status=ConnectorStatus.NOT_CONFIGURED,
    )

    # HIBP API base URL
    BASE_URL = "https://haveibeenpwned.com/api/v3"

    # HIBP API key pattern: 32 hex characters
    API_KEY_PATTERN = r"^[0-9a-fA-F]{32}$"

    def validate_config(self, config: Dict[str, Any]) -> bool:
        """Validate HIBP configuration has required API key.

        The HIBP API key is a 32-character hexadecimal string.
        We validate format only; authentication validity requires a live request.
        """
        api_key = config.get("api_key")
        if not isinstance(api_key, str) or not api_key.strip():
            return False
        import re

        return bool(re.fullmatch(self.API_KEY_PATTERN, api_key.strip()))

    def diagnose(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Diagnose connector configuration and connectivity."""
        if not self.validate_config(config):
            return {
                "ok": False,
                "reason": "api_key ausente ou inválida (deve ser 32 caracteres hexadecimais)",
                "will_call_external": False,
            }

        # Note: Actual connectivity test would consume rate limit/credits
        # We only validate config format here
        return {
            "ok": True,
            "detail": "Configuração válida (formato). Teste de conectividade real consumiria rate limit.",
            "will_call_external": False,
        }

    def validate_query(self, query: str, query_type: QueryType) -> bool:
        """Validate email format for HIBP breachedaccount endpoint.

        The breachedaccount endpoint accepts an email address only.
        Username search is not supported by this endpoint per official docs.
        """
        if query_type != QueryType.EMAIL:
            return False
        return super().validate_query(query, query_type)

    def _build_headers(self, api_key: str) -> Dict[str, str]:
        """Build request headers for HIBP API."""
        return {
            "hibp-api-key": api_key,
            "User-Agent": "Sisifo-OSINT/0.1",
            "Accept": "application/json",
        }

    async def query_with_transport(
        self,
        query: str,
        query_type: QueryType,
        config: Dict[str, Any],
        transport,
        control: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        """Execute HIBP breach lookup using the provided transport.

        Args:
            query: Email address to check
            query_type: Must be QueryType.EMAIL
            config: Connector configuration with api_key
            transport: OsintExecutor instance for HTTP requests
            control: Optional Control object for cancellation checks

        Returns:
            List of breach dictionaries from HIBP API

        Raises:
            OsintExecutionError: For various error conditions with typed codes
        """
        # Check cancellation before starting
        if control:
            control.check()

        api_key = config["api_key"].strip()
        headers = self._build_headers(api_key)

        # HIBP breachedaccount endpoint - encode query as single path segment
        # safe="" ensures all characters are encoded
        url = f"{self.BASE_URL}/breachedaccount/{quote(query, safe='')}"

        # Include truncate=false to get full breach details
        params = {"truncateResponse": "false"}

        try:
            response = await controlled(
                transport.execute_http_query(
                    url=url,
                    method="GET",
                    headers=headers,
                    params=params,
                    config=config,
                    control=control,
                ),
                control,
            )
        except OsintExecutionError as e:
            # Re-raise with HIBP-specific context based on HTTP status
            mapped = self._map_hibp_error(e, endpoint="breachedaccount")
            if mapped.code == "NO_BREACHES_FOUND":
                return []
            raise mapped from e
        except (Cancelled, BudgetExceeded):
            raise
        except Exception as e:
            raise OsintExecutionError(
                "Erro inesperado na consulta HIBP",
                code="QUERY_EXECUTION_FAILED",
                details={},
            ) from e

        # Check cancellation after request
        if control:
            control.check()

        # Parse response
        try:
            breaches = response.json()
        except (ValueError, TypeError) as e:
            raise OsintExecutionError(
                "Resposta HIBP inválida (não é JSON)",
                code="INVALID_JSON",
                details={},
            ) from e

        if not isinstance(breaches, list):
            raise OsintExecutionError(
                "Resposta HIBP inesperada: não é uma lista",
                code="UNEXPECTED_RESPONSE",
                details={"type": type(breaches).__name__},
            )

        return breaches

    def _map_hibp_error(self, error: OsintExecutionError, endpoint: str) -> OsintExecutionError:
        """Map generic HTTP errors to HIBP-specific typed errors.

        Per HIBP API v3 documentation:
        - breachedaccount: 200 (list), 400 (bad format), 401 (unauthorized),
          403 (forbidden - plan), 404 (no breaches), 429 (rate limited)
        - breaches: 200 (list), 401, 403, 429
        - breach/{name}: 200 (detail), 401, 403, 404 (not found), 429
        - dataclasses: 200 (list), 401, 403, 429
        """
        details = dict(error.details)
        details["endpoint"] = endpoint

        if error.code == "HTTP_ERROR":
            status = error.details.get("status_code")
            if status == 404 and endpoint == "breachedaccount":
                # Only breachedaccount maps 404 to a valid empty result.
                return OsintExecutionError(
                    "Nenhuma violação encontrada para este e-mail",
                    code="NO_BREACHES_FOUND",
                    details=details,
                )
            elif status == 401:
                return OsintExecutionError(
                    "Chave de API HIBP inválida ou não autorizada",
                    code="AUTHENTICATION_FAILED",
                    details=details,
                )
            elif status == 403:
                return OsintExecutionError(
                    "Acesso negado pelo HIBP; confira a assinatura, as permissões e o User-Agent",
                    code="ACCESS_FORBIDDEN",
                    details=details,
                )
            elif status == 429:
                retry_after = details.get("retry_after")
                return OsintExecutionError(
                    "Rate limit HIBP excedido. Aguarde antes de tentar novamente.",
                    code="RATE_LIMIT_EXCEEDED",
                    details={**details, "retry_after": retry_after},
                )
            elif status == 404:
                return OsintExecutionError(
                    "Recurso não encontrado no HIBP",
                    code="NOT_FOUND",
                    details=details,
                )

        return error

    def normalize(self, raw: Any, original_query: str = "") -> List[ConnectorResult]:
        """Normalize HIBP breach response to ConnectorResult.

        Args:
            raw: List of breach dictionaries from HIBP API
            original_query: The email address that was queried

        Returns:
            List of ConnectorResult with structured evidence
        """
        if not isinstance(raw, list):
            raise OsintExecutionError(
                "Dados brutos inválidos para normalização: esperado lista",
                code="INVALID_RAW_DATA",
                details={"type": type(raw).__name__},
            )

        results = []
        collected_at = datetime.now(timezone.utc).isoformat()

        for idx, breach in enumerate(raw):
            if not isinstance(breach, dict):
                raise OsintExecutionError("Item HIBP inválido", code="UNEXPECTED_RESPONSE")

            # Validate required fields per HIBP schema
            breach_name = breach.get("Name")
            if not isinstance(breach_name, str) or not breach_name:
                raise OsintExecutionError("Nome de violação ausente", code="UNEXPECTED_RESPONSE")

            # Extract dates
            breach_date = breach.get("BreachDate")
            added_date = breach.get("AddedDate")
            modified_date = breach.get("ModifiedDate")

            # Build evidence with HIBP-specific fields
            # Include IsStealerLog and Attribution when present (documented in newer API versions)
            evidence = {
                "hibp_breach_name": breach_name,
                "hibp_title": breach.get("Title"),
                "hibp_domain": breach.get("Domain"),
                "hibp_breach_date": breach_date,
                "hibp_added_date": added_date,
                "hibp_modified_date": modified_date,
                "hibp_pwn_count": breach.get("PwnCount"),
                "hibp_description": breach.get("Description"),
                "hibp_logo_path": breach.get("LogoPath"),
                "hibp_data_classes": breach.get("DataClasses", []),
                "hibp_is_verified": breach.get("IsVerified", False),
                "hibp_is_fabricated": breach.get("IsFabricated", False),
                "hibp_is_sensitive": breach.get("IsSensitive", False),
                "hibp_is_retired": breach.get("IsRetired", False),
                "hibp_is_spam_list": breach.get("IsSpamList", False),
                "hibp_is_malware": breach.get("IsMalware", False),
                # Optional fields (documented in API v3)
                "hibp_is_stealer_log": breach.get("IsStealerLog"),
                "hibp_attribution": breach.get("Attribution"),
            }

            # Reference URL to HIBP breach page
            reference_url = f"https://haveibeenpwned.com/PwnedWebsites#{breach_name}"

            # Warnings based on breach flags
            warnings = []

            if breach.get("IsSensitive"):
                warnings.append("Violação marcada como sensível pelo HIBP - detalhes limitados.")
            if breach.get("IsFabricated"):
                warnings.append("Violação marcada como fabricada pelo HIBP - pode não ser genuína.")
            if breach.get("IsRetired"):
                warnings.append("Violação aposentada - dados removidos do HIBP.")
            if breach.get("IsMalware"):
                warnings.append("Violação originada de malware/stealer (credenciais roubadas).")
            if breach.get("IsStealerLog"):
                warnings.append(
                    "Violação proveniente de log de stealer (malware de roubo de credenciais)."
                )

            # Limitations - factual statements about the data
            limitations = [
                "Dados baseados no banco do HIBP; pode não incluir todas as violações existentes.",
                "Consulta limitada ao endpoint breachedaccount (apenas e-mail).",
                "Verifique os termos de uso do HIBP para restrições de armazenamento e redistribuição.",
            ]

            result = ConnectorResult(
                source=self.meta.id,
                query=original_query,
                query_type=QueryType.EMAIL,
                collected_at=collected_at,
                original_timestamp=added_date,
                evidence=evidence,
                reference_url=reference_url,
                warnings=warnings,
                limitations=limitations,
            )
            results.append(result)

        return results

    # Additional capability methods - marked as internal, not registered as capabilities
    # These require separate handler registration if exposed via integration catalog

    async def list_breaches(self, config: Dict[str, Any], transport) -> List[Dict[str, Any]]:
        """List all known breaches (GET /breaches).

        Note: This is an internal method, not registered as an executable capability.
        Requires separate integration registration to be available via CLI/Web.
        """
        if not self.validate_config(config):
            raise ValueError("Configuração inválida")

        api_key = config["api_key"].strip()
        headers = self._build_headers(api_key)
        url = f"{self.BASE_URL}/breaches"

        response = await transport.execute_http_query(
            url=url,
            method="GET",
            headers=headers,
            config=config,
        )
        return response.json()

    async def get_breach_detail(
        self, breach_name: str, config: Dict[str, Any], transport
    ) -> Dict[str, Any]:
        """Get details of a specific breach (GET /breach/{name}).

        Note: This is an internal method, not registered as an executable capability.
        """
        if not self.validate_config(config):
            raise ValueError("Configuração inválida")

        api_key = config["api_key"].strip()
        headers = self._build_headers(api_key)
        url = f"{self.BASE_URL}/breach/{quote(breach_name, safe='')}"

        response = await transport.execute_http_query(
            url=url,
            method="GET",
            headers=headers,
            config=config,
        )
        return response.json()

    async def get_dataclasses(self, config: Dict[str, Any], transport) -> List[str]:
        """Get list of data classes (GET /dataclasses).

        Note: This is an internal method, not registered as an executable capability.
        """
        if not self.validate_config(config):
            raise ValueError("Configuração inválida")

        api_key = config["api_key"].strip()
        headers = self._build_headers(api_key)
        url = f"{self.BASE_URL}/dataclasses"

        response = await transport.execute_http_query(
            url=url,
            method="GET",
            headers=headers,
            config=config,
        )
        return response.json()
