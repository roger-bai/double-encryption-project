import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Load the private key.
with open('./uploads/private.key', 'rb') as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password = None,
        backend = default_backend(),
    )

# Load the contents of the file to be signed.
with open('./test files/test.csv.k.txt', 'rb') as f:
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
with open('./uploads/test.csv.k.txt.sig', 'wb') as f:
    f.write(signature)