"""Credit to:
https://stackoverflow.com/questions/50608010/how-to-verify-a-signed-file-in-python
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Generate the public/private key pair.
def gen_pub_pri_keys():
    """
    Generates a public and private key pair and saves the private key 
    to PRIVATE_KEY_LOCATION and the public key to PUBLIC_KEY_LOCATION
    """
    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 4096,
        backend = default_backend(),
    )
    # Save the private key to a file.
    with open(PRIVATE_KEY_LOCATION, 'wb') as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    # Save the public key to a file.
    with open(PUBLIC_KEY_LOCATION, 'wb') as f:
        f.write(
            private_key.public_key().public_bytes(
                encoding = serialization.Encoding.PEM,
                format = serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
