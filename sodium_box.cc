#include "sodium_udf.h"

/** SODIUM_BOX(message, nonce, publicKey, secretKey) RETURNS VARBINARY
 *
 *  Encrypt a message using public-key encryption.
 *
 *  The public key of the recipient is used to encrypt the message
 *  and the secret key of the sender is used to sign it.
 *
 * @CREATE FUNCTION sodium_box RETURNS STRING
 */
MYSQL_STRING_FUNCTION(sodium_box,
{
    // init
    initid->maybe_null = 1;
    initid->max_length = MYSQL_BINARY_STRING;

    REQUIRE_ARGS(4);
    REQUIRE_STRING(0, message);
    REQUIRE_STRING(1, nonce);
    REQUIRE_STRING(2, publicKey);
    REQUIRE_STRING(3, secretKey);
}, {
    // main
    const char *const   message = args->args[0];
    const size_t        messageLength = args->lengths[0];
    if (message == NULL) {
        return_MYSQL_NULL(NULL);
    }

    const char *const nonce = args->args[1];
    if (args->lengths[1] != crypto_box_NONCEBYTES) {
        return_MYSQL_NULL(NULL);
    }

    const char *const publicKey = args->args[2];
    if (args->lengths[2] != crypto_box_PUBLICKEYBYTES) {
        return_MYSQL_NULL(NULL);
    }

    const char *const secretKey = args->args[3];
    if (args->lengths[3] != crypto_box_SECRETKEYBYTES) {
        return_MYSQL_NULL(NULL);
    }

    result = fixed_buffer(result, messageLength + crypto_box_MACBYTES);

    MUST_SUCCEED(Sodium::crypto_box_easy(
        (unsigned char*)result,
        (unsigned char*)message, messageLength,
        (unsigned char*)nonce, (unsigned char*)publicKey, (unsigned char*)secretKey
    ));

    return result;
}, {
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
});


/** SODIUM_BOX_KEYPAIR() RETURNS BINARY
 *
 *  Randomly generate a secret key and a corresponding public key.
 *
 *  SODIUM_BOX_KEYPAIR(seed) RETURNS BINARY
 *
 *  Deterministically derive the key pair from a seed.
 *
 * @CREATE FUNCTION sodium_box_keypair RETURNS STRING
 */
MYSQL_STRING_FUNCTION(sodium_box_keypair,
{
    // init
    initid->maybe_null = 1;
    initid->max_length = MYSQL_BINARY_STRING;

    switch (args->arg_count) {
        case 0:
            break;
        case 1:
            REQUIRE_STRING(0, seed);
            break;
        default:
            strcpy(message, "0-1 arguments required");
            return 1;
    }
}, {
    // main
    result = fixed_buffer(result, crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES + 1);
    result[crypto_box_PUBLICKEYBYTES] = BOUNDARY;

    if (args->arg_count) {
        const char *const seed = args->args[0];
        if (args->lengths[0] != crypto_box_SEEDBYTES) {
            return_MYSQL_NULL(NULL);
        }

        MUST_SUCCEED(Sodium::crypto_box_seed_keypair(
            (unsigned char*)result,
            (unsigned char*)result + crypto_box_PUBLICKEYBYTES + 1,
            (unsigned char*)seed
        ));
    } else {
        MUST_SUCCEED(Sodium::crypto_box_keypair(
            (unsigned char*)result,
            (unsigned char*)result + crypto_box_PUBLICKEYBYTES + 1
        ));
    }

    return result;
}, {
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
});


/** SODIUM_BOX_OPEN(cipher, nonce, publicKey, secretKey) RETURNS VARBINARY
 *
 *  Verify and decrypt a ciphertext.
 *
 *  The public key of the recipient is used to verify the message
 *  and the secret key of the sender is used to decrypt it.
 *
 * @CREATE FUNCTION sodium_box_open RETURNS STRING
 */
MYSQL_STRING_FUNCTION(sodium_box_open,
{
    // init
    initid->maybe_null = 1;
    initid->max_length = MYSQL_BINARY_STRING;

    REQUIRE_ARGS(4);
    REQUIRE_STRING(0, cipher);
    REQUIRE_STRING(1, nonce);
    REQUIRE_STRING(2, publicKey);
    REQUIRE_STRING(3, secretKey);
}, {
    // main
    const char *const   cipher = args->args[0];
    const size_t        cipherLength = args->lengths[0];
    if (cipher == NULL) {
        return_MYSQL_NULL(NULL);
    }

    const char *const nonce = args->args[1];
    if (args->lengths[1] != crypto_box_NONCEBYTES) {
        return_MYSQL_NULL(NULL);
    }

    const char *const publicKey = args->args[2];
    if (args->lengths[2] != crypto_box_PUBLICKEYBYTES) {
        return_MYSQL_NULL(NULL);
    }

    const char *const secretKey = args->args[3];
    if (args->lengths[3] != crypto_box_SECRETKEYBYTES) {
        return_MYSQL_NULL(NULL);
    }

    result = fixed_buffer(result, cipherLength - crypto_box_MACBYTES);

    if (Sodium::crypto_box_open_easy(
            (unsigned char*)result, (unsigned char*)cipher, cipherLength,
            (unsigned char*)nonce, (unsigned char*)publicKey, (unsigned char*)secretKey
        ) != SUCCESS
    ) {
        return_MYSQL_NULL(NULL);
    }

    return result;
}, {
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
});


/** SODIUM_BOX_PK(keyPair) RETURNS BINARY(crypto_box_PUBLICKEYBYTES)
 *
 *  Extract public key from a keypair.
 *
 * @CREATE FUNCTION sodium_box_pk RETURNS STRING
 * @ALIAS FUNCTION sodium_box_publickey RETURNS STRING
 */
SUBSTRING_FUNCTION(sodium_box_pk,
    keyPair, MYSQL_BINARY_STRING,
    0, crypto_box_PUBLICKEYBYTES,
    crypto_box_PUBLICKEYBYTES,
    crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES + 1
);

UDF_STRING_ALIAS(sodium_box_publickey, sodium_box_pk);


/** SODIUM_BOX_SK2PK(secretKey) RETURNS BINARY(crypto_box_PUBLICKEYBYTES)
 *
 *  Compute public key from secret key.
 *
 * @CREATE FUNCTION sodium_box_sk2pk RETURNS STRING
 * @ALIAS FUNCTION sodium_box_publickey_from_secretkey RETURNS STRING
 */
MYSQL_STRING_FUNCTION(sodium_box_sk2pk,
{
    // init
    initid->maybe_null = 1;
    initid->max_length = MYSQL_BINARY_STRING;

    REQUIRE_ARGS(1);
    REQUIRE_STRING(0, secretKey);
}, {
    // main
    const char *    secretKey = args->args[0];
    const size_t    secretKeyLength = args->lengths[0];

    if (secretKeyLength != crypto_box_SECRETKEYBYTES) {
        return_MYSQL_NULL(NULL);
    }

    result = fixed_buffer(result, crypto_box_PUBLICKEYBYTES);

    MUST_SUCCEED(Sodium::crypto_scalarmult_base((unsigned char*)result, (unsigned char*)secretKey));

    return result;
}, {
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
});

UDF_STRING_ALIAS(sodium_box_publickey_from_secretkey, sodium_box_sk2pk);


/** SODIUM_BOX_SEAL(message, publicKey) RETURNS VARBINARY
 *
 *  Encrypt a message using public-key encryption.
 *
 *  The public key of the recipient is used along with a ephemeral key
 *  to encrypt the message.
 *
 * @CREATE FUNCTION sodium_box_seal RETURNS STRING
 */
MYSQL_STRING_FUNCTION(sodium_box_seal,
{
    // init
    initid->maybe_null = 1;
    initid->max_length = MYSQL_BINARY_STRING;

    REQUIRE_ARGS(2);
    REQUIRE_STRING(0, message);
    REQUIRE_STRING(1, publicKey);
}, {
    // main
    const char *const   message = args->args[0];
    const size_t        messageLength = args->lengths[0];
    if (message == NULL) {
        return_MYSQL_NULL(NULL);
    }

    const char *const publicKey = args->args[1];
    if (args->lengths[1] != crypto_box_PUBLICKEYBYTES) {
        return_MYSQL_NULL(NULL);
    }

    result = fixed_buffer(result, messageLength + crypto_box_SEALBYTES);

    MUST_SUCCEED(Sodium::crypto_box_seal(
        (unsigned char*)result,
        (unsigned char*)message, messageLength,
        (unsigned char*)publicKey
    ));

    return result;
}, {
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
});


/** SODIUM_BOX_SEAL_OPEN(cipher, keyPair) RETURNS VARBINARY
 *
 *  Decrypt a ciphertext.
 *
 *  SODIUM_BOX_SEAL_OPEN(cipher, publicKey, secretKey) RETURNS VARBINARY
 *
 *  Decrypt a ciphertext.
 *
 *  The public and secret keys of the recipient are used to verify and
 *  decrypt the message.
 *
 * @CREATE FUNCTION sodium_box_seal_open RETURNS STRING
 */
MYSQL_STRING_FUNCTION(sodium_box_seal_open,
{
    // init
    initid->maybe_null = 1;
    initid->max_length = MYSQL_BINARY_STRING;

    switch (args->arg_count) {
        case 2: {
            REQUIRE_STRING(0, cipher);
            REQUIRE_STRING(1, keyPair);

        } break;
        case 3: {
            REQUIRE_STRING(0, cipher);
            REQUIRE_STRING(1, publicKey);
            REQUIRE_STRING(2, secretKey);
        } break;
        default: {
            strcpy(message, "2-3 arguments required");
            return 1;
        }
    }
}, {
    // main
    const char *const   cipher = args->args[0];
    const size_t        cipherLength = args->lengths[0];
    if (cipher == NULL) {
        return_MYSQL_NULL(NULL);
    }

    const char *        publicKey;
    const char *        secretKey;

    if (args->arg_count > 2) {
        publicKey = args->args[1];
        if (args->lengths[1] != crypto_box_PUBLICKEYBYTES) {
            return_MYSQL_NULL(NULL);
        }

        secretKey = args->args[2];
        if (args->lengths[2] != crypto_box_SECRETKEYBYTES) {
            return_MYSQL_NULL(NULL);
        }
    } else {
        const size_t keyPairLength = (crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES + 1);

        if (args->lengths[1] != keyPairLength
            || args->args[1][crypto_box_PUBLICKEYBYTES] != BOUNDARY
        ) {
            return_MYSQL_NULL(NULL);
        }

        publicKey = args->args[1];
        secretKey = args->args[1] + crypto_box_PUBLICKEYBYTES + 1;
    }
    result = fixed_buffer(result, cipherLength - crypto_box_SEALBYTES);

    MUST_SUCCEED(Sodium::crypto_box_seal_open(
        (unsigned char*)result,
        (unsigned char*)cipher, cipherLength,
        (unsigned char*)publicKey,
        (unsigned char*)secretKey)
    );

    return result;
}, {
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
});


/** sodium_box_sk(keyPair) RETURNS BINARY(crypto_box_SECRETKEYBYTES)
 *
 *  Extract secret key from a keypair.
 *
 * @CREATE FUNCTION sodium_box_sk RETURNS STRING
 * @ALIAS FUNCTION sodium_box_secretkey RETURNS STRING
 */
SUBSTRING_FUNCTION(sodium_box_sk,
    keyPair, MYSQL_BINARY_STRING,
    crypto_box_PUBLICKEYBYTES + 1, crypto_box_SECRETKEYBYTES,
    crypto_box_PUBLICKEYBYTES,
    crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES + 1
);

UDF_STRING_ALIAS(sodium_box_secretkey, sodium_box_sk);

