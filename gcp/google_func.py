"""
Credit to
https://hackersandslackers.com/manage-files-in-google-cloud-storage-with-python/
"""

from os import listdir
from os.path import isfile, join
from google.cloud import storage

bucketName = BUCKET_NAME
bucketFolder = BUCKET_FOLDER
localFolder = LOCAL_FOLDER

# Authentication to bucket
storage_client = storage.Client.from_service_account_json(JSON_OF_SERVICE_ACCOUNT)
bucket = storage_client.get_bucket(bucketName)

def upload_files(bucketName):
    """
    Uploads files in LOCAL_FOLDER to BUCKET_NAME/BUCKET_FOLDER
    """
    files = [f for f in listdir(localFolder) if isfile(join(localFolder, f))]
    for file in files:
        localFile = localFolder + file
        blob = bucket.blob(bucketFolder + file)
        blob.upload_from_filename(localFile)
    return f'Uploaded {files} to "{bucketName}" bucket.'

def list_files(bucketName):
    """
    Lists the files in BUCKET_NAME/BUCKET_FOLDER
    """
    files = bucket.list_blobs(prefix=bucketFolder)
    fileList = [file.name for file in files if '.' in file.name]
    return fileList

def download_file(bucketFile, localFolder):
    """
    Downloads the files in BUCKET_NAME/BUCKET_FOLDER to LOCAL_FOLDER
    """
    blob = bucket.blob(bucketFile)
    fileName = blob.name.split('/')[-1]
    blob.download_to_filename(localFolder + fileName)
    return f'{fileName} downloaded from bucket.'
