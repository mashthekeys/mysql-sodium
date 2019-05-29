# mysql-sodium
Mysql UDF bindings for LibSodium

## Usage

In the shell (assuming your Mysql plugin directory is ``/usr/lib64/mysql/plugin/``):

```bash
$ sudo cp sodium.so /usr/lib64/mysql/plugin/sodium.so
```

Then in Mysql (for each function):

```mysql
CREATE FUNCTION crypto_pwhash_str RETURNS STRING SONAME 'sodium.so';
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

✔︎ ``crypto_pwhash_str`` — Get an ASCII-encoded hash


### v0.1 - Port core functionality

``crypto_auth_verify`` — Verifies that the tag is valid for the message

``crypto_auth`` — Compute a tag for the message

``crypto_box_keypair_from_secretkey_and_publickey``

``crypto_box_keypair`` — Randomly generate a secret key and a corresponding public key

``crypto_box_open`` — Verify and decrypt a ciphertext

``crypto_box_publickey_from_secretkey``

``crypto_box_publickey``

``crypto_box_seal_open`` — Decrypt the ciphertext

``crypto_box_seal`` — Encrypt a message

``crypto_box_secretkey``

``crypto_box_seed_keypair`` — Deterministically derive the key pair from a single key

``crypto_box`` — Encrypt a message

``crypto_generichash`` — Get a hash of the message

``crypto_kdf_derive_from_key`` — Derive a subkey

``crypto_kx_client_session_keys``

``crypto_kx_keypair`` — Creates a new sodium keypair

``crypto_kx_publickey``

``crypto_kx_secretkey``

``crypto_kx_seed_keypair``

``crypto_kx_server_session_keys``

``crypto_pwhash_str_needs_rehash``

``crypto_pwhash_str_verify`` — Verifies that a password matches a hash

``crypto_pwhash`` — Derive a key from a password

``crypto_secretbox_open`` — Verify and decrypt a ciphertext

``crypto_secretbox`` — Encrypt a message

``crypto_sign_detached`` — Sign the message

``crypto_sign_keypair_from_secretkey_and_publickey``

``crypto_sign_keypair`` — Randomly generate a secret key and a corresponding public key

``crypto_sign_open`` — Check that the signed message has a valid signature

``crypto_sign_publickey_from_secretkey`` — Extract the public key from the secret key

``crypto_sign_publickey``

``crypto_sign_secretkey``

``crypto_sign_seed_keypair`` — Deterministically derive the key pair from a single key

``crypto_sign_verify_detached`` — Verify signature for the message

``crypto_sign`` — Sign a message

``crypto_shorthash`` — Compute a fixed-size fingerprint for the message

``sodium_pad`` — Add padding data

``sodium_unpad`` — Remove padding data



### v0.1 - Port keygen utilities

``crypto_auth_keygen`` — Get random bytes for key

``crypto_generichash_keygen`` — Get random bytes for key

``crypto_kdf_keygen`` — Get random bytes for key

``crypto_secretbox_keygen`` — Get random bytes for key

``crypto_shorthash_keygen`` — Get random bytes for key



### v0.2 - Port group_generichash aggregate function

``crypto_generichash_final`` — Complete the hash

``crypto_generichash_init`` — Initialize a hash

``crypto_generichash_update`` — Add message to a hash




### v0.3 - Support for alternate algorithms

``crypto_pwhash_scryptsalsa208sha256_str_verify`` — Verify that the password is a valid password verification string

``crypto_pwhash_scryptsalsa208sha256_str`` — Get an ASCII encoded hash

``crypto_pwhash_scryptsalsa208sha256`` — Derives a key from a password

``crypto_sign_ed25519_pk_to_curve25519`` — Convert an Ed25519 public key to a Curve25519 public key

``crypto_sign_ed25519_sk_to_curve25519`` — Convert an Ed25519 secret key to a Curve25519 secret key


### Before v1.0 - Review AEAD support

``crypto_aead_aes256gcm_decrypt`` — Decrypt in combined mode with precalculation

``crypto_aead_aes256gcm_encrypt`` — Encrypt in combined mode with precalculation

``crypto_aead_aes256gcm_is_available`` — Check if hardware supports AES256-GCM

``crypto_aead_aes256gcm_keygen`` — Get random bytes for key

``crypto_aead_chacha20poly1305_decrypt`` — Verify that the ciphertext includes a valid tag

``crypto_aead_chacha20poly1305_encrypt`` — Encrypt a message

``crypto_aead_chacha20poly1305_ietf_decrypt`` — Verify that the ciphertext includes a valid tag

``crypto_aead_chacha20poly1305_ietf_encrypt`` — Encrypt a message

``crypto_aead_chacha20poly1305_ietf_keygen`` — Get random bytes for key

``crypto_aead_chacha20poly1305_keygen`` — Get random bytes for key

``crypto_aead_xchacha20poly1305_ietf_decrypt``

``crypto_aead_xchacha20poly1305_ietf_encrypt``

``crypto_aead_xchacha20poly1305_ietf_keygen``


### Unportable functionality

``crypto_secretstream_xchacha20poly1305_init_pull``

``crypto_secretstream_xchacha20poly1305_init_push``

``crypto_secretstream_xchacha20poly1305_keygen``

``crypto_secretstream_xchacha20poly1305_pull``

``crypto_secretstream_xchacha20poly1305_push``

``crypto_secretstream_xchacha20poly1305_rekey``

``crypto_stream_keygen`` — Get random bytes for key

``crypto_stream_xor`` — Encrypt a message

``crypto_stream`` — Generate a deterministic sequence of bytes from a seed


### Utilities (ported only if required)

``crypto_scalarmult_base`` — Alias of crypto_box_publickey_from_secretkey

``crypto_scalarmult`` — Compute a shared secret given a user's secret key and another user's public key

``sodium_add`` — Add large numbers

``sodium_base642bin``

``sodium_bin2base64``

``sodium_bin2hex`` — Encode to hexadecimal

``sodium_compare`` — Compare large numbers

``sodium_hex2bin`` — Decodes a hexadecimally encoded binary string

``sodium_increment`` — Increment large number

``sodium_memcmp`` — Test for equality in constant-time

``sodium_memzero`` — Overwrite buf with zeros
