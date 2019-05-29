# mysql-sodium
Mysql UDF bindings for LibSodium

## Usage

In the shell (assuming your Mysql plugin directory is ``/usr/lib64/mysql/plugin/``):

```bash
$ sudo cp sodium.so /usr/lib64/mysql/plugin/sodium.so
```

Then in Mysql (for each function):

```mysql
CREATE FUNCTION sodium_pwhash_str RETURNS STRING SONAME 'sodium.so';
```

## Compiling from Source

Required: ``libsodium-devel``

Mysql 8 includes are included in mysql-sodium, so the 3GB ``mysql-devel`` package is *not required*.

```bash
$ gcc -shared -std=c++11 -Imysql-8-include -fPIC -lsodium -o sodium.so sodium.cc
```

## Roadmap
Goal: Provide UDFs for Mysql to implement support for LibSodium.

### v0.0.1 - Feasibility Test

✔︎ ``sodium_pwhash_str`` — Get an ASCII-encoded hash


### v0.1 - Port core functionality

``sodium_auth`` — Compute a tag for the message

``sodium_auth_verify`` — Verifies that the tag is valid for the message

``sodium_box`` — Encrypt a message

x ``sodium_box_keypair_from_secretkey_and_publickey``

``sodium_box_keypair`` — Randomly generate a secret key and a corresponding public key

``sodium_box_open`` — Verify and decrypt a ciphertext

``sodium_box_publickey``

x ``sodium_box_publickey_from_secretkey``

``sodium_box_seal`` — Encrypt a message

``sodium_box_seal_open`` — Decrypt the ciphertext

``sodium_box_secretkey``

``sodium_box_seed_keypair`` — Deterministically derive the key pair from a single key

``sodium_generichash`` — Get a hash of the message

``sodium_kdf_derive_from_key`` — Derive a subkey

``sodium_kx_client_session_keys``

``sodium_kx_keypair`` — Creates a new sodium keypair

``sodium_kx_publickey``

``sodium_kx_secretkey``

``sodium_kx_seed_keypair``

``sodium_kx_server_session_keys``

``sodium_pwhash`` — Derive a key from a password

``sodium_pwhash_str_needs_rehash``

``sodium_pwhash_str_verify`` — Verifies that a password matches a hash

``sodium_secretbox`` — Encrypt a message

``sodium_secretbox_open`` — Verify and decrypt a ciphertext

``sodium_sign`` — Sign a message

``sodium_sign_detached`` — Sign the message

x ``sodium_sign_keypair_from_secretkey_and_publickey``

``sodium_sign_keypair`` — Randomly generate a secret key and a corresponding public key

``sodium_sign_open`` — Check that the signed message has a valid signature

``sodium_sign_publickey_from_secretkey`` — Extract the public key from the secret key

``sodium_sign_publickey``

``sodium_sign_secretkey``

``sodium_sign_seed_keypair`` — Deterministically derive the key pair from a single key

``sodium_sign_verify_detached`` — Verify signature for the message

``sodium_shorthash`` — Compute a fixed-size fingerprint for the message

``_sodium_pad`` — Add padding data

``_sodium_unpad`` — Remove padding data



### v0.1 - Port keygen utilities

``sodium_auth_keygen`` — Get random bytes for key

``sodium_generichash_keygen`` — Get random bytes for key

``sodium_kdf_keygen`` — Get random bytes for key

``sodium_secretbox_keygen`` — Get random bytes for key

``sodium_shorthash_keygen`` — Get random bytes for key



### v0.2 - group_generichash aggregate function

``sodium_generichash_init`` — Initialize a hash

``sodium_generichash_update`` — Add message to a hash

``sodium_generichash_final`` — Complete the hash



### v0.3 - Support for alternate algorithms

``sodium_pwhash_scryptsalsa208sha256`` — Derives a key from a password

``sodium_pwhash_scryptsalsa208sha256_str`` — Get an ASCII encoded hash

``sodium_pwhash_scryptsalsa208sha256_str_verify`` — Verify that the password is a valid password verification string

``sodium_sign_ed25519_pk_to_curve25519`` — Convert an Ed25519 public key to a Curve25519 public key

``sodium_sign_ed25519_sk_to_curve25519`` — Convert an Ed25519 secret key to a Curve25519 secret key


### Before v1.0 - Review AEAD support

``sodium_aead_aes256gcm_decrypt`` — Decrypt in combined mode with precalculation

``sodium_aead_aes256gcm_encrypt`` — Encrypt in combined mode with precalculation

``sodium_aead_aes256gcm_is_available`` — Check if hardware supports AES256-GCM

``sodium_aead_aes256gcm_keygen`` — Get random bytes for key

``sodium_aead_chacha20poly1305_decrypt`` — Verify that the ciphertext includes a valid tag

``sodium_aead_chacha20poly1305_encrypt`` — Encrypt a message

``sodium_aead_chacha20poly1305_ietf_decrypt`` — Verify that the ciphertext includes a valid tag

``sodium_aead_chacha20poly1305_ietf_encrypt`` — Encrypt a message

``sodium_aead_chacha20poly1305_ietf_keygen`` — Get random bytes for key

``sodium_aead_chacha20poly1305_keygen`` — Get random bytes for key

``sodium_aead_xchacha20poly1305_ietf_decrypt``

``sodium_aead_xchacha20poly1305_ietf_encrypt``

``sodium_aead_xchacha20poly1305_ietf_keygen``


### Unportable functionality

``sodium_secretstream_xchacha20poly1305_init_pull``

``sodium_secretstream_xchacha20poly1305_init_push``

``sodium_secretstream_xchacha20poly1305_keygen``

``sodium_secretstream_xchacha20poly1305_pull``

``sodium_secretstream_xchacha20poly1305_push``

``sodium_secretstream_xchacha20poly1305_rekey``

``sodium_stream`` — Generate a deterministic sequence of bytes from a seed

``sodium_stream_keygen`` — Get random bytes for key

``sodium_stream_xor`` — Encrypt a message


### Utilities (ported only if required)

``sodium_add`` — Add large numbers

``sodium_base642bin``

``sodium_bin2base64``

``sodium_bin2hex`` — Encode to hexadecimal

``sodium_compare`` — Compare large numbers

``sodium_hex2bin`` — Decodes a hexadecimally encoded binary string

``sodium_increment`` — Increment large number

``sodium_memcmp`` — Test for equality in constant-time

``sodium_memzero`` — Overwrite buf with zeros

``sodium_scalarmult`` — Compute a shared secret given a user's secret key and another user's public key

``sodium_scalarmult_base`` — Alias of sodium_box_publickey_from_secretkey
