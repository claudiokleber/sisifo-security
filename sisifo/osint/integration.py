"""OSINT integrations using the shared connector executor."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from sisifo.core.config import load_service_config
from sisifo.core.integration import IntegrationCapability, IntegrationMeta, IntegrationStatus
from sisifo.osint.contract import QueryType
from sisifo.osint.dummy import DummyConnector
from sisifo.osint.executor import run_query
from sisifo.osint.hibp import HibpConnector


class DummyInputs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    query: str = Field(min_length=1, max_length=2048)
    query_type: Literal["domain", "ip"]


class HibpInputs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    query: str = Field(
        min_length=1, max_length=2048, description="Endereço de e-mail para consultar"
    )
    query_type: Literal["email"] = Field(
        default="email", description="Tipo de consulta (apenas 'email' suportado)"
    )


def dummy_connector_handler(inputs, options, context, control):
    control.check()
    results = run_query(
        DummyConnector(),
        inputs["query"],
        QueryType(inputs["query_type"]),
        context["credentials"]["osint_dummy"],
        control,
    )
    control.check()
    return {"results": [r.model_dump(mode="json") for r in results]}


def hibp_connector_handler(inputs, options, context, control):
    control.check()
    results = run_query(
        HibpConnector(),
        inputs["query"],
        QueryType.EMAIL,
        context["credentials"]["osint_hibp"],
        control,
    )
    control.check()
    return {"results": [r.model_dump(mode="json") for r in results]}


def register_dummy_integration(catalog):
    configured = DummyConnector().validate_config(load_service_config("osint_dummy"))
    catalog.register(
        IntegrationMeta(
            id="osint_dummy",
            name="OSINT Dummy",
            description="Consulta simulada; sem acesso externo",
            version="0.1.0",
            category="data_connector",
            entry_point=__name__,
            status=IntegrationStatus.EXPERIMENTAL
            if configured
            else IntegrationStatus.NOT_CONFIGURED,
            execution_limits={
                "max_duration_seconds": 30,
                "max_output_size_mib": 1,
                "max_concurrency": 1,
            },
            capabilities=[
                IntegrationCapability(
                    name="query",
                    description="Consulta simulada de domínio/IP",
                    requires_credentials=True,
                    timeout_seconds=30,
                    external=True,
                )
            ],
        )
    )
    catalog.register_handler(
        "osint_dummy",
        "query",
        dummy_connector_handler,
        DummyInputs,
        policy={"credential_services": ["osint_dummy"]},
    )


def register_hibp_integration(catalog):
    catalog.register_availability(
        "osint_hibp",
        lambda: (
            IntegrationStatus.AVAILABLE
            if HibpConnector().validate_config(load_service_config("osint_hibp"))
            else IntegrationStatus.NOT_CONFIGURED
        ),
    )
    configured = HibpConnector().validate_config(load_service_config("osint_hibp"))
    catalog.register(
        IntegrationMeta(
            id="osint_hibp",
            name="Have I Been Pwned",
            description="Consulta exposição de e-mails em violações (HIBP API v3 - breachedaccount)",
            version="0.1.0",
            category="data_connector",
            entry_point=__name__,
            status=IntegrationStatus.AVAILABLE if configured else IntegrationStatus.NOT_CONFIGURED,
            execution_limits={
                "max_duration_seconds": 60,
                "max_output_size_mib": 5,
                "max_concurrency": 1,
            },
            capabilities=[
                IntegrationCapability(
                    name="query",
                    description="Consulta violações de e-mail no HIBP (endpoint breachedaccount)",
                    requires_credentials=True,
                    timeout_seconds=60,
                    external=True,
                    consumes_credits=False,  # Subscription requirements are determined by HIBP, not this flag
                    input_types=["email"],
                    output_types=["breach_list"],
                )
            ],
        )
    )
    catalog.register_handler(
        "osint_hibp",
        "query",
        hibp_connector_handler,
        HibpInputs,
        policy={"credential_services": ["osint_hibp"], "approval_required": True},
    )


def register_osint_integrations(catalog):
    """Register all OSINT integrations."""
    register_dummy_integration(catalog)
    register_hibp_integration(catalog)
