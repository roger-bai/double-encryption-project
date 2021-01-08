import hvac

# Vault server url
vault_url = 'http://127.0.0.1:8200'

def create_key(key_name: str, url: str = vault_url):
    """
    Creates a key of name key_name.
    """
    client = hvac.Client(url=vault_url)
    
    client.secrets.transit.create_key(name=key_name)