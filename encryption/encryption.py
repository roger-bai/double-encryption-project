from Crypto.Cipher import AES
from Crypto.Random import new as Random
from hashlib import sha256
from base64 import b64encode, b64decode
import scrypt
import csv
import itertools


class AESCipher:
    """
    credit to https://stackoverflow.com/a/54024595
    """
    def __init__(self, data, key):
        self.data   = data
        self.key    = sha256(key).digest()[:32]
        self.pad    = lambda s: s + (16 - len(s) % 16) * chr(16 - len(s) % 16)
        self.unpad  = lambda s: s[:-ord(s[len(s) - 1:])]

    def encrypt(self):
        plain_text  = self.pad(self.data)
        iv          = Random().read(AES.block_size)
        cipher      = AES.new(self.key, AES.MODE_GCM, iv)
        return b64encode(iv + cipher.encrypt(plain_text.encode())).decode()

    def decrypt(self):
        cipher_text = b64decode(self.data.encode())
        iv          = cipher_text[:16]
        cipher      = AES.new(self.key,AES.MODE_GCM,iv)
        return self.unpad(cipher.decrypt(cipher_text[16:])).decode()


def encrypt_CSV(file_name, columns_to_encrypt = None):
    """
    encrypts specified columns of CSV file with corresponding keys using AES-256 in GCM mode
    parameters:
        file_name:          name of CSV file to encrypt
        columns_to_encrypt: unspecified ('None'), or array with indices of columns to encrypt
    """
    file = open(file_name, 'r')
    reader_, reader = itertools.tee(csv.reader(file, delimiter=','))
    columns = len(next(reader_))
    if not columns_to_encrypt:
        columns_to_encrypt = [_ for _ in range(columns)]
    del reader_

    if len(list(set(columns_to_encrypt))) < len(columns_to_encrypt):
        raise ValueError("repeated column number")
    elif len(columns_to_encrypt) != len(set(columns_to_encrypt).intersection(set(range(columns)))):
        raise ValueError("index does not correspond to column")

    column_keys = {}
    for i in range(len(columns_to_encrypt)):
        column_keys[columns_to_encrypt[i]] = Random().read(16)
    header = next(reader) 
    encrypted_data = []
    for line in reader:
        if line:
            encrypted_row = {}
            for i in range(len(line)):
                if i in columns_to_encrypt:
                    encrypted_row[header[i]] = AESCipher(line[i], column_keys[i]).encrypt()
                else:
                    encrypted_row[header[i]] = line[i]
            encrypted_data.append(encrypted_row)
    file.close()
    with open(file_name, 'w') as enc_file:
        writer = csv.DictWriter(enc_file, fieldnames = header)
        writer.writeheader()
        for row in encrypted_data:
            writer.writerow(row)  
    return column_keys


def decrypt_CSV(file_name, column_keys):
    """
    decrypts CSV file encrypted with encrypt_CSV
    parameters:
        file_name:   name of CSV file to decrypt
        key:         16-byte secret key
        column_keys: dictionary of column numbers and their corresponding keys
    """
    file = open(file_name, 'r')
    reader_, reader = itertools.tee(csv.reader(file))
    columns = len(next(reader_))
    del reader_
        
    header = next(reader) 
    decrypted_data = []
    for line in reader:
        if line:
            decrypted_row = {}
            for i in range(len(line)):
                if i in column_keys:
                    decrypted_row[header[i]] = AESCipher(line[i], column_keys[i]).decrypt()
                else:
                    decrypted_row[header[i]] = line[i]
            decrypted_data.append(decrypted_row)
    file.close()
    with open(file_name, 'w') as enc_file:
        writer = csv.DictWriter(enc_file, fieldnames = header)
        writer.writeheader()
        for row in decrypted_data:
            writer.writerow(row)
