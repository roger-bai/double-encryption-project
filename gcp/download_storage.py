# Script to download a .csv and the associated DEKs, and then decrypts the file

import encryption
import vault
import google_func
import os

# Download file
bucketFile = FILE_TO_DOWNLOAD_IN_GCP
bucketKeys = ENCRYPTED_DEKS_OF_FILE_TO_DOWNLOAD_IN_GCP
localFolder = LOCAL_FOLDER
google_func.download_file(bucketFile, localFolder)
google_func.download_file(bucketKeys, localFolder)

downloaded_file = DOWNLOADED_FILE_IN_LOCAL_FOLDER
encrypted_DEKs_file = ENCRYPTED_DEKS_IN_LOCAL_FOLDER

# Get Encrypted DEKs
encrypted_DEKs_str = {}
with open(encrypted_DEKs_file) as f:
    for line in f:
        (key, val) = line.split()
        encrypted_DEKs_str[int(key)] = val

# Decrypt DEKs
DEKs = {}
for k in encrypted_DEKs_str:
    DEKs[k] = vault.decode_base64(vault.decrypt('KEK',
            encrypted_DEKs_str[k].encode('utf-8'))).encode('latin-1')

# Decrypt File
encryption.decrypt_CSV(downloaded_file, DEKs)

# Delete Encrypted DEKs
os.remove(encrypted_DEKs_file)
