"""
Credit to:
https://stackoverflow.com/questions/50608010/how-to-verify-a-signed-file-in-python
"""

import base64
import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

def verify_sig(PUBLIC_KEY_LOCATION, PAYLOAD_LOCATION, SIGNATURE_LOCATION):
    """
    Verifies that SIGNATURE_LOCATION is a signature of PAYLOAD_LOCATION using
    PUBLIC_KEY_LOCATION
    """
    # Load the public key.
    with open(PUBLIC_KEY_LOCATION, 'rb') as f:
        public_key = load_pem_public_key(f.read(), default_backend())

    # Load the payload contents and the signature.
    with open(PAYLOAD_LOCATION, 'rb') as f:
        payload_contents = f.read()
    with open(SIGNATURE_LOCATION, 'rb') as f:
        signature = base64.b64decode(f.read())

    # Perform the verification.
    try:
        public_key.verify(
            signature,
            payload_contents,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    except cryptography.exceptions.InvalidSignature as e:
        print('ERROR: Payload and/or signature files failed verification!')
        quit()
