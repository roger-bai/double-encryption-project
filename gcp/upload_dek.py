# Script to upload DEKs to cloud VM to decrypt a .csv file

import vault
import google_func
import os
import subprocess
import sym_key_gen
import signing
import ocsp

# OCSP check
hostname = 'console.cloud.google.com'
ocsp_status = ocsp.ocsp_check(hostname)
if ocsp_status != 'OCSP Status: GOOD':
    print(ocsp_status)
    quit()

# Get encrypted DEKs
bucketFile = FILE_TO_DECRYPT_IN_BUCKET
bucketKeys = ENCRYPTED_DEKS_IN_BUCKET
localFolder = LOCAL_FOLDER
google_func.download_file(bucketKeys, localFolder)

encrypted_DEKs_file = ENCRYPTED_DEKS_IN_LOCAL_FOLDER
cols = COLUMNS_TO_DECRYPT

# Decrypt required DEKs
encrypted_DEKs_str = {}
with open(encrypted_DEKs_file) as f:
    for line in f:
        if int(line[0]) in cols:
            (key, val) = line.split()
            encrypted_DEKs_str[int(key)] = val

DEKs = {}
for k in encrypted_DEKs_str:
    DEKs[k] = vault.decode_base64(vault.decrypt('KEK',
              encrypted_DEKs_str[k].encode('utf-8'))).encode('latin-1')

# File to upload
with open(DEKS_IN_LOCAL_FOLDER, 'w') as f:
    for k in DEKs:
        f.write(str(k) + '\t ' + vault.encode_base64(DEKs[k].decode('latin-1')) + "\n")

# Create signature of file
sym_key_gen.gen_pub_pri_keys()
pubkey = PUBLIC_KEY_LOCATION
privkey = PRIVATE_KEY_LOCATION

file_to_sign = DEKS_IN_LOCAL_FOLDER
signing.sign_file(privkey, file_to_sign)
signature = SIGNATURE_LOCATION

os.remove(privkey) # Best to use srm to securely remove

# Upload File to VM
for f in [pubkey, signature, file_to_sign]:
    subprocess.call(["scp", "-i", SSH_KEY, f,
                 FOLDER_IN_VM_TO_UPLOAD_TO])

# Delete files (better to use srm)
for f in [file_to_sign, encrypted_DEKs_file, pubkey, signature]:
    os.remove(f)
