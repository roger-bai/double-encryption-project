# Create and encrypts DEKs. Sends encrypted DEKs to cloud storage and DEKs to cloud VM

import vault
import google_func
import fileinput
import sys
import os
import subprocess
import encryption
import sym_key_gen
import signing
import ocsp

# OCSP check
hostname = 'console.cloud.google.com'
ocsp_status = ocsp.ocsp_check(hostname)
if ocsp_status != 'OCSP Status: GOOD':
    print(ocsp_status)
    quit()

# Get old DEKs
bucketKeys = ENCRYPTED_DEKS_IN_BUCKET
localFolder = LOCAL_FOLDER
google_func.download_file(bucketKeys, localFolder)

encrypted_DEKs_file = ENCRYPTED_DEKS_IN_LOCAL_FOLDER
cols = COLUMNS_TO_ENCRYPT

# Create DEKs
DEKs = encryption.generate_DEKs(cols)

# Encrypt DEKs
encrypted_DEKs = {}
for k in DEKs:
    encrypted_DEKs[k] = vault.encrypt('KEK',
                        vault.encode_base64(DEKs[k].decode('latin-1')))

# Renew Encrypted DEKs file
for line in fileinput.input(encrypted_DEKs_file, inplace=True):
    for k in encrypted_DEKs:
        if line.startswith(str(k)):
            line = str(k) + '\t ' + encrypted_DEKs[k].decode('utf-8') + '\n'
        sys.stdout.write(line)

# Create new DEKs file
new_deks = NEW_DEKS_LOCATION
with open(new_deks, 'w') as f:
    for k in DEKs:
        f.write(str(k) + '\t ' + vault.encode_base64(DEKs[k].decode('latin-1')) + "\n")

# Sign file
sym_key_gen.gen_pub_pri_keys()
pubkey = PUBLIC_KEY_LOCATION
privkey = PRIVATE_KEY_LOCATION

signing.sign_file(privkey, new_deks)
signature = SIGNATURE_LOCATION

os.remove(privkey)

# Upload DEK to VM
for f in [pubkey, signature, new_deks]:
    subprocess.call(["scp", "-i", SSH_KEY, f,
                 FOLDER_IN_VM_TO_UPLOAD_TO])

# Delete files (best to use srm)
for f in [new_deks, pubkey, signature]:
    os.remove(f)

# Upload encrypted DEK to storage
google_func.upload_files(google_func.bucketName)
os.remove(encrypted_DEKs_file)
