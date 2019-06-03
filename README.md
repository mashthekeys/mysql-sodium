# mysql-sodium
Mysql UDF bindings for LibSodium

## Usage

In the shell (assuming your Mysql plugin directory is ``/usr/lib64/mysql/plugin/``):

```bash
$ sudo cp sodium.so /usr/lib64/mysql/plugin/sodium.so
```

Then in Mysql (for each function):

```mysql
CREATE FUNCTION block_pad RETURNS STRING SONAME 'sodium.so';
CREATE FUNCTION block_unpad RETURNS STRING SONAME 'sodium.so';
CREATE FUNCTION sodium_auth RETURNS STRING SONAME 'sodium.so';
CREATE FUNCTION sodium_auth_keygen RETURNS STRING SONAME 'sodium.so';
CREATE FUNCTION sodium_auth_verify RETURNS INTEGER SONAME 'sodium.so';
/* ... */
```

Each function operates independently, so an application need only load those functions which 
are required for its purposes.

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

✔︎ ``block_pad`` 
— Add padding data

✔︎ ``block_unpad`` 
— Remove padding data

✔︎ ``sodium_auth`` 
— Compute a tag for the message

✔︎ ``sodium_auth_verify`` 
— Verifies that the tag is valid for the message

✔︎ ``sodium_box`` 
— Encrypt a message

✔︎ ``sodium_box_keypair()`` 
— Randomly generate a secret key and a corresponding public key

✔︎ ``sodium_box_keypair(seed)`` 
— Deterministically derive the key pair from a single key

✔︎ ``sodium_box_keypair_from_secretkey_and_publickey`` 
– Should be replaced with CONCAT

✔︎ ``sodium_box_open`` 
— Verify and decrypt a ciphertext

✔︎ ``sodium_box_pk``
– Extract public key from keypair. \
Aliased to ``sodium_box_publickey``

✔︎ ``sodium_box_seal`` 
— Encrypt a message

✔︎ ``sodium_box_seal_open`` 
— Decrypt the ciphertext

✔︎ ``sodium_box_sk``
– Extract secret key from keypair. \
Aliased to ``sodium_box_secretkey``

✔︎ ``sodium_box_sk2pk``, alias ``sodium_box_publickey_from_secretkey``
– Compute public key from secret key.

✔︎ ``sodium_generichash`` 
— Get a hash of the message

✔︎ ``sodium_kdf`` 
— Derive a subkey \
Aliased to ``sodium_kdf_derive_from_key``

✔︎ ``sodium_kx_client_session_keys``

✔︎ ``sodium_kx_keypair()``
— Creates a new sodium keypair

✔︎ ``sodium_kx_keypair(seed)``
— Deterministically creates a new sodium keypair

✔︎ ``sodium_kx_pk``
– Extract public key from keypair. \
Aliased to ``sodium_kx_publickey``

✔︎ ``sodium_kx_sk``
– Extract secret key from keypair. \
Aliased to ``sodium_kx_secretkey``

✔︎ ``sodium_kx_server_session_keys``

✔︎ ``sodium_pw``
— Derive a self-contained salted ASCII hash from a password. \
Aliased to ``sodium_pwhash_str``

✔︎ ``sodium_pw_outdated``
— Determine whether a stored salted hash meets security parameters. \
Aliased to ``sodium_pwhash_str_needs_rehash``

✔︎ ``sodium_pw_verify``
— Verifies that a password matches a hash. \
Aliased to ``sodium_pwhash_str_verify``

✔︎ ``sodium_pwhash``
— Derive a key from a password

✔︎ ``sodium_secretbox``
— Encrypt a message

✔︎ ``sodium_secretbox_open``
— Verify and decrypt a ciphertext

✔︎ ``sodium_sign(detached, message, secretKey)``
— Sign a message

✔︎ ``sodium_sign_keypair_from_secretkey_and_publickey``
– Should be replaced with CONCAT().

✔︎ ``sodium_sign_keypair()``
— Randomly generate a secret key and a corresponding public key

✔︎ ``sodium_sign_keypair(seed)``
— Deterministically derive the key pair from a single key

✔︎ ``sodium_sign_open`` 
— Get the content of a signed message, or NULL if invalid

✔︎ ``sodium_sign_sk2pk`` 
— Compute the public key from the secret key. \
Aliased to ``sodium_sign_publickey_from_secretkey``

✔︎ ``sodium_sign_pk``
– Extract public key from keypair. \
Aliased to ``sodium_sign_publickey``

✔︎ ``sodium_sign_sk``
– Extract secret key from keypair. \
Aliased to ``sodium_sign_secretkey``

✔︎ ``sodium_sign_verify(signature, message, pk)`` 
— Verify signature for the message

✔︎ ``sodium_sign_verify(signedMessage, pk)`` 
– Verify a signed message

✔︎ ``sodium_shorthash`` 
— Compute a fixed-size fingerprint for short messages



### v0.1 - Port keygen utilities

✔︎ ``sodium_auth_keygen`` 
— Get random bytes for key

✔︎ ``sodium_generichash_keygen`` 
— Get random bytes for key

✔︎ ``sodium_kdf_keygen`` 
— Get random bytes for key

✔︎ ``sodium_secretbox_keygen`` 
— Get random bytes for key

✔︎ ``sodium_shorthash_keygen`` 
— Get random bytes for key



### v0.2 - group_generichash aggregate function

✔︎ ``group_generichash(hashLength, message)``
— Generate a hash of length ``hashLength`` which generates a hash for each 
  group of ``message``s. 

✔︎ ``group_generichash(hashLength, message, key)``
— Generate a hash of length ``hashLength`` which generates a hash for all 
  ``message`` strings in each group, using a single ``key`` per group. 



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

``sodium_stream``

``sodium_stream_keygen``

``sodium_stream_xor``


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
