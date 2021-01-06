import sys
import subprocess

# implement pip as a subprocess to install packages:
for package in ['ed25519', 'ocsp-checker']:
  subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
  
import ed25519
from ocspchecker import ocspchecker

def sign_message(msg: bytes):
  """ 
  Returns a public/private key pair and signs the msg using the private key. 
  Returns the signed msg and the public key to verify the signature.
  """
  
  # msg needs to be in bytes.
  privkey, pubkey = ed25519.create_keypair()
  signature = privkey.sign(msg, encoding='hex')
  return signature, pubkey
  
def verify_signature(msg: bytes, signature: bytes, pubkey) -> bool:
  """
  Uses the pubkey to check that the signed msg is signature. If so, returns True, else False.
  """
  
  try:
    pubkey.verify(signature, msg, encoding='hex')
    print(True)
  except:
    print(False)

def ocsp_check(server: str) -> str:
  """
  Takes a website and checks their certificate status using OCSP.
  """
  
  return ocspchecker.get_ocsp_status(server)[-1]
