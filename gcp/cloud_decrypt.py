# Script for cloud VM to decrypt a .csv file.

import encryption
import os
import vault
import verification

test_file = FILE_TO_DECRYPT

# Verify Signature
pubkey = PUBLIC_KEY_LOCATION
key_file = DEKS_OF_FILE_TO_DECRYPT
signature = SIGNATURE_LOCATION
verification.verify_sig(pubkey, key_file, signature)

os.remove(pubkey) # Best to use srm or equivalent
os.remove(signature)

# Use DEK to decrypt file
DEKs = {}
with open(key_file) as f:
    for line in f:
        (key, val) = line.split()
        DEKs[int(key)] = vault.decode_base64(val).encode('latin-1')

encryption.decrypt_CSV(test_file, DEKs)

# Delete DEKs (best to use srm)
os.remove(key_file)
