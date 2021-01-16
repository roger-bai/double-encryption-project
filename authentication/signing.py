"""
Credit to:
https://stackoverflow.com/questions/50608010/how-to-verify-a-signed-file-in-python
"""

import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

def sign_file(PRIVATE_KEY_LOCATION, FILE_TO_BE_SIGNED):
    """
    Signs FILE_TO_BE_SIGNED with PRIVATE_KEY_LOCATION and creates a signature at SIGNATURE_LOCATION
    """
    # Load the private key.
    with open(PRIVATE_KEY_LOCATION, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password = None,
            backend = default_backend(),
        )
    # Load the contents of the file to be signed.
    with open(FILE_TO_BE_SIGNED, 'rb') as f:
        payload = f.read()
    # Sign the payload file.
    signature = base64.b64encode(
        private_key.sign(
            payload,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    )
    with open(SIGNATURE_LOCATION, 'wb') as f:
        f.write(signature)
