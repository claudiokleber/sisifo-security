"""Integration registry - central registration of all integrations."""

from sisifo.core.integration import CapabilityCatalog
from sisifo.modules.network.integration import register_network_integration
from sisifo.osint.integration import register_osint_integrations


def create_catalog() -> CapabilityCatalog:
    """Build one catalog for an application lifecycle or CLI invocation."""
    catalog = CapabilityCatalog()
    register_network_integration(catalog)
    register_osint_integrations(catalog)
    return catalog
