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