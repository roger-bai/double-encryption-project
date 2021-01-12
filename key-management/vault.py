import hvac
import base64

# Vault server url
vault_url = 'http://127.0.0.1:8200'

def encode_base64(input_string: str) -> str:
    """
    Takes a string and returns its base64 encoding as a string.
    """
    input_bytes = input_string.encode('utf8')
    encoded_bytes = base64.urlsafe_b64encode(input_bytes)

    return encoded_bytes.decode('ascii')

def decode_base64(input_string: str) -> str:
    """
    Takes a base64-encoded string and returns the decoded string.
    """
    input_bytes = input_string.encode('utf8')
    decoded_bytes = base64.urlsafe_b64decode(input_bytes)

    return decoded_bytes.decode('ascii')

def create_key(key_name: str, url: str = vault_url):
    """
    Creates a key of name key_name.
    """
    client = hvac.Client(url=url)
    
    client.secrets.transit.create_key(name=key_name)

def encrypt(key_name: str, plaintext: str, url: str = vault_url) -> bytes:
    """
    Encrypts plaintext given in base64 encoding using key corresponding to 
    key_name and returns the ciphertext.

    Output ciphertext formatted as vault:version:ciphertext
    """
    client = hvac.Client(url=url)

    encrypt_data_response = client.secrets.transit.encrypt_data(
        name = key_name,
        plaintext = plaintext
    )
    ciphertext = encrypt_data_response['data']['ciphertext']
    
    return ciphertext.encode('utf8')

def decrypt(key_name: str, ciphertext:bytes, url: str = vault_url) -> str:
    """
    Decrypts the ciphertext given as bytes using key corresponding to key_name 
    and returns the base64-encoded plaintext.
    """
    client = hvac.Client(url=url)

    decrypt_data_response = client.secrets.transit.decrypt_data(
        name = key_name,
        ciphertext = ciphertext.decode('ascii')
    )
    plaintext = decrypt_data_response['data']['plaintext']

    return plaintext