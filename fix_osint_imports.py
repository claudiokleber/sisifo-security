with open('sisifo/osint/integration.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix the imports
old = '''"""OSINT dummy connector integration handler."""

from typing import Any, Dict

from sisifo.core.integration import (
    ExecutionMode,
    IntegrationCapability,
    IntegrationCategory,
    IntegrationMeta,
    IntegrationStatus,
)
from sisifo.osint.contract import QueryType
from sisifo.osint.dummy import DummyConnector'''

new = '''"""OSINT dummy connector integration handler."""

from typing import Any, Dict

from sisifo.core.integration import (
    CapabilityCatalog,
    ExecutionMode,
    IntegrationCapability,
    IntegrationCategory,
    IntegrationMeta,
    IntegrationStatus,
    ExecutionLimits,
)
from sisifo.osint.contract import QueryType
from sisifo.osint.dummy import DummyConnector'''

content = content.replace(old, new)
with open('sisifo/osint/integration.py', 'w', encoding='utf-8') as f:
    f.write(content)
print('Fixed OSINT integration imports')