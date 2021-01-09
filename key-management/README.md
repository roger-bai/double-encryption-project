# Requires Vault server running in dev mode
# Do NOT use in production yet

Uses HashiCorp Vault for key management and encryption/decryption of DEKs.
Currently requires Vault in dev mode for dev purposes.

## Vault setup
Setup Vault in dev mode:

`$ vault server -dev`

On a new terminal window export the (default) Vault address:

`$ export VAULT_ADDR='http://127.0.0.1:8200'`

Set up Transit secrets engine:

`$ vault secrets enable transit`

## Variables
`vault_url`

URL of the Vault server.
Defaulted at `http://127.0.0.1:8200`

## Functions
`encode_base64(input_string: str) -> str`

Takes a string and returns its URL-safe base64 encoding as a string.

`decode_base64(input_string: str) -> str`

Takes a URL-safe base64-encoded string and returns its decoding as an ASCII string.

`create_key(key_name: str, url: str = vault_url)`

Creates a key of name `key_name` for Vault server at `url` (default value at `vault_url`).
Default mode is `aes256-gcm96`.

`encrypt(key_name: str, plaintext: str, url: str = vault_url) -> str`

Encrypts uses the key corresponding to `key_name` to encrypt the plaintext given in base64 encoding and returns the ciphertext.
The output ciphertext is of the form vault:[version]:[ciphertext].

`decrypt(key_name: str, ciphertext:str, url: str = vault_url) -> str`

Decrypts the ciphertext using key corresponding to `key_name` and returns the base64-encoded plaintext.