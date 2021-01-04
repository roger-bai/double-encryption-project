pip install ecpy
from ecpy.curves import Curve
from ecpy.keys import ECPrivateKey
from ecpy.eddsa import EDDSA
import secrets, hashlib, binascii

# Getting the elliptic curve.
curve = Curve.get_curve('Ed448')

# The signer.
signer = EDDSA(hashlib.shake_256, hash_len=114)

# Random key generation.
privkey = ECPrivateKey(secrets.randbits(57*8), curve)
pubkey = signer.get_public_key(privkey, hashlib.shake_256, hash_len=114)

# Seeing what the keys are and the point on the curve for public key.
print("Private key (57 bytes):", privkey)
print("Public key (57 bytes):", binascii.hexlify(curve.encode_point(pubkey.W)))
print("Public key (point):", pubkey)

# Sign a message.
msg = b"Sign this message."
signature = signer.sign(msg, privkey)

# Verify the signature.
valid = signer.verify(msg, signature, pubkey)
print("Valid signature?", valid)
