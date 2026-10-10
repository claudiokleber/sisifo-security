"""Offline network capabilities backed by the existing NetworkService."""
from pydantic import BaseModel, ConfigDict, Field

from sisifo.core.integration import IntegrationCapability, IntegrationMeta
from sisifo.modules.network.models import DisplayFilter
from sisifo.modules.network.service import NetworkService


class CaptureInputs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    capture_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_-]+$")
    display_filter: str = Field(default="", max_length=500)


class DetailInputs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    capture_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_-]+$")
    packet_number: int = Field(ge=1)


class PacketOptions(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


def network_analyze_handler(inputs, options, context, control):
    service = NetworkService()
    capture_id = inputs["capture_id"]
    display_filter = DisplayFilter(expression=inputs["display_filter"])
    outputs = {}
    operations = {
        "packets": lambda: service.list_packets(capture_id, display_filter,
                                                options["offset"], options["limit"], control=control),
        "protocol_stats": lambda: service.get_protocol_stats(capture_id, display_filter, control=control),
        "endpoints": lambda: service.get_endpoints(capture_id, display_filter, control=control),
        "conversations": lambda: service.get_conversations(capture_id, display_filter, control=control),
        "dns_summary": lambda: service.get_dns_summary(capture_id, display_filter, control=control),
        "tcp_summary": lambda: service.get_tcp_summary(capture_id, display_filter, control=control),
    }
    def encode(value):
        if isinstance(value, BaseModel):
            return value.model_dump(mode="json")
        if isinstance(value, list):
            return [encode(v) for v in value]
        if isinstance(value, dict):
            return {k: encode(v) for k, v in value.items()}
        return value
    for name, operation in operations.items():
        control.check()
        outputs[name] = encode(operation())
        control.progress(name, {"outputs": outputs})
    return outputs


def network_packet_detail_handler(inputs, options, context, control):
    control.check()
    return NetworkService().get_packet_detail(
        inputs["capture_id"], inputs["packet_number"], control=control).model_dump(mode="json")


def register_network_integration(catalog):
    available = NetworkService().discover_tools().tshark_path
    catalog.register(IntegrationMeta(
        id="network_analysis", name="Network Analysis", description="Análise offline com TShark",
        version="1.0.0", category="tool", entry_point=__name__,
        status="available" if available else "not_installed", dependencies=["tshark"],
        execution_limits={"max_duration_seconds": 300, "max_output_size_mib": 10, "max_concurrency": 2},
        capabilities=[IntegrationCapability(name="analyze", description="Estatísticas e pacotes", timeout_seconds=300),
                      IntegrationCapability(name="packet_detail", description="Detalhes de pacote", timeout_seconds=60)]))
    catalog.register_handler("network_analysis", "analyze", network_analyze_handler,
                             CaptureInputs, options_schema=PacketOptions)
    catalog.register_handler("network_analysis", "packet_detail", network_packet_detail_handler,
                             DetailInputs)
