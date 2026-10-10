"""Data models for the network module."""

from datetime import UTC, datetime
from enum import Enum
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from sisifo.core.schema import Identifier


class CaptureSource(str, Enum):
    """Source of a capture."""

    CAPTURED = "captured"
    IMPORTED = "imported"


class CaptureStatus(str, Enum):
    """Status of a capture operation."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"
    PARTIAL = "partial"


class NetworkInterface(BaseModel):
    """Represents a network interface available for capture."""

    id: str = Field(..., description="Interface identifier (e.g., 'eth0', '\\Device\\NPF_{...}')")
    name: str = Field(..., description="Human-readable name")
    description: str = Field(default="", description="Detailed description")
    loopback: bool = Field(default=False, description="Whether this is a loopback interface")
    up: bool = Field(default=True, description="Whether the interface is up")
    addresses: list[str] = Field(default_factory=list, description="IP addresses assigned to this interface")
    speeds: list[int] = Field(default_factory=list, description="Supported speeds in Mbps")

    model_config = ConfigDict(extra="forbid")


class CaptureFilter(BaseModel):
    """Capture filter using BPF syntax."""

    expression: str = Field(default="", description="BPF filter expression (e.g., 'tcp port 443')")
    description: str = Field(default="", description="Human-readable description")

    model_config = ConfigDict(extra="forbid")


class DisplayFilter(BaseModel):
    """Display filter using Wireshark/TShark syntax."""

    expression: str = Field(default="", description="Wireshark display filter expression (e.g., 'dns')")
    description: str = Field(default="", description="Human-readable description")

    model_config = ConfigDict(extra="forbid")


class CaptureLimits(BaseModel):
    """Limits for a capture session."""

    max_duration_seconds: int = Field(default=60, ge=1, le=86400, description="Maximum capture duration in seconds")
    max_file_size_mib: int = Field(default=100, ge=1, le=10240, description="Maximum file size in MiB")
    max_packets: int = Field(default=100000, ge=1, le=10000000, description="Maximum number of packets to capture")
    max_concurrent_captures: int = Field(default=2, ge=1, le=8, description="Maximum concurrent captures")

    model_config = ConfigDict(extra="forbid")


class CaptureConfig(BaseModel):
    """Configuration for a capture session."""

    interface_id: str = Field(..., description="Interface identifier to capture from")
    capture_filter: CaptureFilter = Field(default_factory=CaptureFilter)
    limits: CaptureLimits = Field(default_factory=CaptureLimits)
    output_directory: Optional[str] = Field(default=None, description="Custom output directory (relative to data root)")
    ring_buffer: bool = Field(default=False, description="Enable ring buffer with multiple files")
    ring_buffer_files: int = Field(default=5, ge=2, le=50, description="Number of ring buffer files")

    model_config = ConfigDict(extra="forbid")


class CaptureResult(BaseModel):
    """Result of a capture or import operation."""

    id: Identifier = Field(default_factory=lambda: uuid4().hex)
    source: CaptureSource = Field(default=CaptureSource.CAPTURED)
    status: CaptureStatus = Field(default=CaptureStatus.PENDING)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    interface_id: Optional[str] = None
    interface_name: Optional[str] = None
    capture_filter: Optional[str] = None
    display_filter: Optional[str] = None
    limits: Optional[CaptureLimits] = None
    file_path: str = Field(..., description="Path to the PCAP/PCAPNG file")
    file_size: int = Field(default=0, description="File size in bytes")
    file_sha256: Optional[str] = Field(default=None, description="SHA-256 hash of the capture file")
    packet_count: int = Field(default=0, description="Total packets in capture")
    dropped_packets: int = Field(default=0, description="Packets dropped by the capture engine")
    dropped_by_interface: int = Field(default=0, description="Packets dropped by the interface")
    tshark_version: Optional[str] = Field(default=None, description="TShark version used for analysis")
    dumpcap_version: Optional[str] = Field(default=None, description="Dumpcap version used for capture")
    error: Optional[str] = Field(default=None, description="Error message if failed")
    environment: str = Field(default="native", description="Capture environment: 'native' or 'docker'")
    is_docker: bool = Field(default=False, description="Whether capture was performed in Docker")

    model_config = ConfigDict(extra="forbid")


class PacketSummary(BaseModel):
    """Summary of a single packet for listing."""

    number: int = Field(..., description="Packet number in capture")
    time: float = Field(..., description="Time since capture start in seconds")
    time_iso: str = Field(..., description="ISO timestamp of packet")
    source: str = Field(..., description="Source address")
    destination: str = Field(..., description="Destination address")
    protocol: str = Field(..., description="Highest layer protocol")
    length: int = Field(..., description="Packet length in bytes")
    info: str = Field(..., description="Summary info from dissector")

    model_config = ConfigDict(extra="forbid")


class ProtocolHierarchyItem(BaseModel):
    """Item in protocol hierarchy statistics."""

    protocol: str = Field(..., description="Protocol name")
    packets: int = Field(..., description="Packet count")
    bytes: int = Field(..., description="Byte count")
    percentage_packets: float = Field(..., description="Percentage of total packets")
    percentage_bytes: float = Field(..., description="Percentage of total bytes")

    model_config = ConfigDict(extra="forbid")


class EndpointStats(BaseModel):
    """Endpoint statistics."""

    address: str = Field(..., description="Endpoint address (IP, MAC, etc.)")
    type: str = Field(..., description="Address type (IPv4, IPv6, Ethernet, etc.)")
    packets_rx: int = Field(default=0, description="Packets received")
    packets_tx: int = Field(default=0, description="Packets transmitted")
    bytes_rx: int = Field(default=0, description="Bytes received")
    bytes_tx: int = Field(default=0, description="Bytes transmitted")

    model_config = ConfigDict(extra="forbid")


class ConversationStats(BaseModel):
    """Conversation statistics."""

    endpoint_a: str = Field(..., description="First endpoint address")
    endpoint_b: str = Field(..., description="Second endpoint address")
    protocol: str = Field(..., description="Conversation protocol (TCP, UDP, etc.)")
    packets: int = Field(default=0, description="Total packets")
    bytes: int = Field(default=0, description="Total bytes")
    packets_a_to_b: int = Field(default=0, description="Packets A→B")
    bytes_a_to_b: int = Field(default=0, description="Bytes A→B")
    packets_b_to_a: int = Field(default=0, description="Packets B→A")
    bytes_b_to_a: int = Field(default=0, description="Bytes B→A")
    start_time: float = Field(default=0.0, description="Start time relative to capture")
    end_time: float = Field(default=0.0, description="End time relative to capture")
    duration: float = Field(default=0.0, description="Conversation duration in seconds")

    model_config = ConfigDict(extra="forbid")


class ProtocolStats(BaseModel):
    """Protocol distribution statistics."""

    capture_id: Identifier
    total_packets: int = Field(default=0)
    total_bytes: int = Field(default=0)
    by_protocol: list[ProtocolHierarchyItem] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")


class PacketDetail(BaseModel):
    """Detailed packet information including protocol tree and hex dump."""

    number: int
    time: float
    time_iso: str
    source: str
    destination: str
    protocol: str
    length: int
    info: str
    layers: list[dict] = Field(default_factory=list, description="Protocol layer tree")
    hex_dump: str = Field(default="", description="Hex/ASCII dump of packet bytes")
    original_length: int = Field(default=0, description="Original packet length on wire (frame.len)")
    captured_length: int = Field(default=0, description="Captured packet length (frame.caplen)")
    extracted_length: int = Field(default=0, description="Bytes actually extracted from hex dump")
    hex_dump_error: Optional[str] = Field(default=None, description="Error message if hex dump extraction failed")

    model_config = ConfigDict(extra="forbid")


class NetworkDiagnostics(BaseModel):
    """Network diagnostics and capability information."""

    platform: str = Field(..., description="Operating system platform")
    is_docker: bool = Field(default=False, description="Running inside Docker")
    dumpcap_path: Optional[str] = Field(default=None, description="Path to dumpcap executable")
    tshark_path: Optional[str] = Field(default=None, description="Path to tshark executable")
    wireshark_path: Optional[str] = Field(default=None, description="Path to wireshark executable")
    npcap_version: Optional[str] = Field(default=None, description="Npcap version (Windows)")
    libpcap_version: Optional[str] = Field(default=None, description="libpcap version (Linux)")
    dumpcap_version: Optional[str] = Field(default=None, description="Dumpcap version")
    tshark_version: Optional[str] = Field(default=None, description="TShark version")
    interfaces: list[NetworkInterface] = Field(default_factory=list)
    capture_permissions: bool = Field(default=False, description="Has permission to capture")
    permission_details: str = Field(default="", description="Details about capture permissions")
    storage_path: str = Field(..., description="Capture storage path")
    storage_available_mib: int = Field(default=0, description="Available storage in MiB")
    max_concurrent_captures: int = Field(default=2)
    active_captures: int = Field(default=0)
    recent_captures: list[CaptureResult] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")


class AIAnalysisInput(BaseModel):
    """Sanitized capture summary for AI analysis."""

    capture_id: Identifier
    capture_source: CaptureSource
    duration_seconds: float
    total_packets: int
    total_bytes: int
    protocol_distribution: list[ProtocolHierarchyItem]
    top_endpoints: list[EndpointStats]
    top_conversations: list[ConversationStats]
    dns_queries: list[dict] = Field(default_factory=list)
    tcp_indicators: dict = Field(default_factory=dict)
    anomalies: list[str] = Field(default_factory=list)
    supporting_packet_numbers: list[int] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")


class AIAnalysisResult(BaseModel):
    """Result of AI-assisted capture analysis."""

    capture_id: Identifier
    analysis_id: str
    status: str
    facts_observed: list[str] = Field(default_factory=list)
    hypotheses: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    diagnostic_recommendations: list[str] = Field(default_factory=list)
    evidence_references: list[dict] = Field(default_factory=list)
    provider: str
    model: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    model_config = ConfigDict(extra="forbid")


class CaptureReport(BaseModel):
    """Complete capture analysis report."""

    capture_id: Identifier
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    summary: CaptureResult
    protocol_stats: ProtocolStats
    endpoints: list[EndpointStats]
    conversations: list[ConversationStats]
    dns_summary: dict = Field(default_factory=dict)
    tcp_summary: dict = Field(default_factory=dict)
    anomalies: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")