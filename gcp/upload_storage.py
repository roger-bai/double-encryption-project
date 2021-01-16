# Script to encrypt and upload a file to Google Cloud Storage

import ocsp
import vault
import google_func
import encryption

# OCSP check
hostname = 'console.cloud.google.com'
ocsp_status = ocsp.ocsp_check(hostname)
if ocsp_status != 'OCSP Status: GOOD':
    print(ocsp_status)
    quit()

# The file directory and columns to encrypt
testfile = TEST_FILE_LOCATION
cols = COLUMNS_OF_TEST_FILE_TO_ENCRYPT

# DEKs and replace file with encrypted file
DEKs = encryption.generate_DEKs(cols)
encryption.encrypt_CSV(testfile, DEKs)

# Encrypt DEKs
# Sometimes fails depending on the 'latin-1' bytes.
encrypted_DEKs = {}
for k in DEKs:
    encrypted_DEKs[k] = vault.encrypt('KEK',
                        vault.encode_base64(DEKs[k].decode('latin-1')))

# Create file with encrypted DEKs
with open(testfile + '.txt', 'w') as f:
    for k in encrypted_DEKs:
        f.write(str(k) + '\t ' + encrypted_DEKs[k].decode('utf-8') + "\n")

# Upload to storage
google_func.upload_files(google_func.bucketName)
