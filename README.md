# wallet-tool
Example app to control the wallet. Supported commands include listing slots,
resetting the token (deleting all objects), generating, importing and deleting 
key pairs, signing data, as well as changing the user PIN-code. Commands that
operate on a specific wallet accept the``--wallet-id`` option; when omitted,
wallet identifier ``0`` is used. When generating a key pair both ``--key-id``
and ``--key-label`` must be specified. Use ``--get-mnemonic`` to get mnemonic
phrase during key pair generation. ``--force`` parameter usage deletes all
objects.

Put the wtpkcs11ecp library into programm working directory.

## PIN-code

Commands that need authentication ask for the PIN-code instead of taking it from
the command line, so it does not end up in the shell history or in the process
list. On a terminal the input is hidden; when the standard input is redirected
the PIN is read as one line, which keeps the tool usable from scripts:

```
python main.py --list-keys --pin
echo 12345678 | python main.py --list-keys --pin
```

``--pin`` still accepts a value directly when that is what you want. ``--new-pin``
behaves the same way, and ``--change-pin`` without values asks for the current
and then the new PIN-code, in that order.

For ``--list-keys`` the PIN-code stays optional: without ``--pin`` at all nothing
is asked and only public keys are listed.

```
python main.py --list-wallets
python main.py --show-wallet-info --wallet-id 0
python main.py --generate-key secp256 --wallet-id 0 --pin --key-id my_bitcoin_masterkey_id --key-label my_secure_bitcoin_masterkey
python main.py --generate-key secp256 --wallet-id 0 --pin --key-id my_eth_key_masterkey_id --key-label my_shared_eth_masterkey --get-mnemonic
python main.py --generate-key ed25519 --wallet-id 0 --pin --key-id my_sol_key_masterkey_id --key-label my_secure_sol_masterkey
python main.py --import-key "24 words mnemonic phrase" --wallet-id 0 --pin --key-id my_imported_eth_masterkey_id --key-label my_imported_eth_masterkey
python main.py --list-keys --wallet-id 0 --pin
python main.py --sign --key-number 1 --data "text to sign" --wallet-id 0 --pin
python main.py --sign --key-number 1 --hash 0011223344556677889900112233445566778899001122334455667788990011 --wallet-id 0 --pin
python main.py --delete-key --key-number 1 --wallet-id 0 --pin
python main.py --delete-key --force --wallet-id 0 --pin
python main.py --change-pin --wallet-id 0 --pin --new-pin
python main.py --version
```
