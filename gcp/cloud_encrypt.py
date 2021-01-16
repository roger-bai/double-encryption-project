# Script for cloud VM to encrypt file

import encryption
import vault
import os
import verification

test_file = FILE_TO_ENCRYPT

# Verify Signature
pubkey = PUBLIC_KEY_LOCATION
new_deks = DEKS_LOCATION
signature = SIGNATURE_LOCATION
verification.verify_sig(pubkey, new_deks, signature)

os.remove(pubkey) # Best to use srm or equivalent
os.remove(signature)

# Get New DEKs
DEKs_str = {}
with open(new_deks) as f:
    for line in f:
        (key, val) = line.split()
        DEKs_str[int(key)] = val

DEKs = {}
for k in DEKs_str:
    DEKs[k] = vault.decode_base64(DEKs_str[k]).encode('latin-1')

# Encrypt file
encryption.encrypt_CSV(test_file, DEKs)

# Delete DEKs (best to use srm or equivalent)
os.remove(new_deks)
