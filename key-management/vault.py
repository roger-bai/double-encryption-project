import hvac

# Vault server url
vault_url = 'http://127.0.0.1:8200'

def create_key(key_name: str, url: str = vault_url):
    """
    Creates a key of name key_name.
    """
    client = hvac.Client(url=url)
    
    client.secrets.transit.create_key(name=key_name)

def encrypt(key_name: str, plaintext: str, url: str = vault_url) -> str:
    """
    Encrypts plaintext given in base64 encoding using key corresponding to 
    key_name and returns the ciphertext.
    """
    client = hvac.Client(url=url)

    encrypt_data_response = client.secrets.transit.encrypt_data(
        name = key_name,
        plaintext = plaintext
    )
    ciphertext = encrypt_data_response['data']['ciphertext']
    
    return ciphertext

def decrypt(key_name: str, ciphertext:str, url: str = vault_url) -> str:
    """
    Decrypts the ciphertext using key corresponding to key_name and returns the
    base64-encoded plaintext.
    """
    client = hvac.Client(url=url)

    decrypt_data_response = client.secrets.transit.decrypt_data(
        name = key_name,
        ciphertext = ciphertext
    )
    plaintext = decrypt_data_response['data']['plaintext']

    return plaintext