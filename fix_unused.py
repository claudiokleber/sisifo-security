with open('sisifo/osint/integration.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix the unused variable
old = '''def register_dummy_integration(catalog):
    """Register the OSINT dummy connector integration."""
    connector = DummyConnector()'''

new = '''def register_dummy_integration(catalog):
    """Register the OSINT dummy connector integration."""
    DummyConnector()'''

content = content.replace(old, new)
with open('sisifo/osint/integration.py', 'w', encoding='utf-8') as f:
    f.write(content)
print('Fixed unused variable')