from ecpy.curves import Curve
from ecpy.keys import ECPrivateKey
from ecpy.eddsa import EDDSA
import secrets, hashlib, binascii

# Getting the elliptic curve.
curve = Curve.get_curve('Ed448')

# The signer.
signer = EDDSA(hashlib.shake_256, hash_len=114)

def sign_message(msg: bytes):
    """
    Creates a public/private key pair and signs the msg using the private key.
    Returns the signed msg and the public key to verify the signature.
    """

    # msg needs to be in bytes.
    privkey = ECPrivateKey(secrets.randbits(57 * 8), curve)
    pubkey = signer.get_public_key(privkey, hashlib.shake_256, hash_len=114)
    signature = signer.sign(msg, privkey)
    return signature, pubkey


def verify_signature(msg: bytes, signature: bytes, pubkey) -> bool:
    """
    Uses the pubkey to check that the signed msg is signature. If so, returns True, else False.
    """

    return signer.verify(msg, signature, pubkey)
