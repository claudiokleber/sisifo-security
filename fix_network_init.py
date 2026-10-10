with open('sisifo/modules/network/__init__.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix the import order
old = '''"""Network monitoring and analysis module for Sísifo."""

from .integration import register_network_integration
from .models import (
    CaptureConfig,
    CaptureResult,
    ConversationStats,
    EndpointStats,
    NetworkInterface,
    PacketSummary,
    ProtocolStats,
)
from .service import NetworkService

__all__ = [
    "CaptureConfig",
    "CaptureResult",
    "ConversationStats",
    "EndpointStats",
    "NetworkInterface",
    "NetworkService",
    "PacketSummary",
    "ProtocolStats",
    "register_network_integration",
]'''

new = '''"""Network monitoring and analysis module for Sísifo."""

from .models import (
    CaptureConfig,
    CaptureResult,
    ConversationStats,
    EndpointStats,
    NetworkInterface,
    PacketSummary,
    ProtocolStats,
)
from .service import NetworkService
from .integration import register_network_integration

__all__ = [
    "CaptureConfig",
    "CaptureResult",
    "ConversationStats",
    "EndpointStats",
    "NetworkInterface",
    "NetworkService",
    "PacketSummary",
    "ProtocolStats",
    "register_network_integration",
]'''

content = content.replace(old, new)
with open('sisifo/modules/network/__init__.py', 'w', encoding='utf-8') as f:
    f.write(content)
print('Fixed network __init__.py imports')