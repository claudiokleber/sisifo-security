"""Test HIBP integration with mocked transport."""
from unittest.mock import MagicMock, AsyncMock
from sisifo.osint.hibp import HibpConnector
from sisifo.osint.contract import QueryType

async def test_hibp():
    from unittest.mock import MagicMock
    
    conn = HibpConnector()
    config = {'api_key': 'a' * 32}
    
    transport = MagicMock()
    mock_response = MagicMock()
    mock_response.json.return_value = [
        {
            'Name': 'Adobe',
            'Title': 'Adobe',
            'Domain': 'adobe.com',
            'BreachDate': '2013-10-04',
            'AddedDate': '2013-12-04T00:00:00Z',
            'ModifiedDate': '2013-12-04T00:00:00Z',
            'PwnCount': 152445165,
            'Description': 'In October 2013, Adobe suffered a data breach...',
            'LogoPath': 'https://haveibeenpwned.com/Content/Images/PwnedLogos/Adobe.png',
            'DataClasses': ['Email addresses', 'Password hints', 'Passwords', 'Usernames'],
            'IsVerified': True,
            'IsFabricated': False,
            'IsSensitive': False,
            'IsRetired': False,
            'IsSpamList': False,
            'IsMalware': False,
            'IsStealerLog': False,
            'Attribution': None,
        }
    ]
    
    transport = MagicMock()
    transport.execute_http_query = MagicMock(return_value=mock_response)
    
    from sisifo.osint.hibp import HibpConnector
    from sisifo.osint.contract import QueryType
    
    conn = HibpConnector()
    config = {'api_key': 'a' * 32}
    
    results = await conn.query_with_transport('test@example.com', 'email', config, transport)
    print('Results:', len(results))
    if results:
        print('First breach:', results[0].get('Name'))
    else:
        print('No results')

import asyncio
asyncio.run(test())