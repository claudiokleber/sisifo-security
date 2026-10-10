with open('sisifo/modules/network/integration.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix the imports
old = '''"""Network analysis integration handler."""

from typing import Any, Dict

from sisifo.core.integration import (
    IntegrationCapability,
    IntegrationCategory,
    IntegrationMeta,
)
from sisifo.modules.network.service import NetworkService'''

new = '''"""Network analysis integration handler."""

from typing import Any, Dict

from sisifo.core.integration import (
    CapabilityCatalog,
    IntegrationCapability,
    IntegrationCategory,
    IntegrationMeta,
    IntegrationStatus,
)
from sisifo.modules.network.service import NetworkService'''

content = content.replace(old, new)
with open('sisifo/modules/network/integration.py', 'w', encoding='utf-8') as f:
    f.write(content)
print('Fixed network integration imports')