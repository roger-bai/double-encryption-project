pip install ed25519
import ed25519

# Create the public and private keys.

privkey, pubkey = ed25519.create_keypair()

# To see what the keys look like.
print("Private Key (32 bytes):", privkey.to_ascii(encoding='hex'))
print("Public Key (32 bytes):", pubkey.to_ascii(encoding='hex'))

# Signing a message.
msg = b"Sign this message."
signature = privkey.sign(msg, encoding='hex')

# Verification of signed message.
try:
  pubkey.verify(signature, msg, encoding='hex')
  print("The signature is valid.")
except:
  print("The signature is invalid.")
