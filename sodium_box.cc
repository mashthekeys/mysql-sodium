#include "sodium_udf.h"

/** sodium_box(message, nonce, publicKey, secretKey) RETURNS STRING */
MYSQL_STRING_FUNCTION(sodium_box,
{
    // init
    REQUIRE_ARGS(4);
    REQUIRE_STRING(0, message);
    REQUIRE_STRING(1, nonce);
    REQUIRE_STRING(2, publicKey);
    REQUIRE_STRING(3, secretKey);

    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    const char *const message = args->args[0];
    size_t messageLength = args->lengths[0];
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


/** sodium_box_keypair() RETURNS STRING */
MYSQL_STRING_FUNCTION(sodium_box_keypair,
{
    // init
    REQUIRE_ARGS(0);

    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    result = fixed_buffer(result, crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES);

    MUST_SUCCEED(Sodium::crypto_box_keypair(
        (unsigned char*)result,
        (unsigned char*)result + crypto_box_PUBLICKEYBYTES
    ));

    return result;
}, {
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
});


/** sodium_box_open(cipher, nonce, publicKey, secretKey) RETURNS STRING */
MYSQL_STRING_FUNCTION(sodium_box_open,
{
    // init
    REQUIRE_ARGS(4);
    REQUIRE_STRING(0, cipher);
    REQUIRE_STRING(1, nonce);
    REQUIRE_STRING(2, publicKey);
    REQUIRE_STRING(3, secretKey);

    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    const char *const cipher = args->args[0];
    size_t cipherLength = args->lengths[0];
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


/* sodium_box_publickey(keyPair) RETURNS BINARY STRING */
SUBSTRING_FUNCTION(sodium_box_publickey,
    keyPair, MYSQL_BINARY_STRING,
    0, crypto_box_PUBLICKEYBYTES,
    crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES
);


/* sodium_box_publickey_from_secretkey(secretKey) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_box_publickey_from_secretkey,
{
    // init
    REQUIRE_ARGS(1);
    REQUIRE_STRING(0, secretKey);
    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    const char *secretKey = args->args[0];
    size_t      secretKeyLength = args->lengths[0];

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


/** sodium_box_seal(message, publicKey) RETURNS STRING */
MYSQL_STRING_FUNCTION(sodium_box_seal,
{
    // init
    REQUIRE_ARGS(2);
    REQUIRE_STRING(0, message);
    REQUIRE_STRING(1, publicKey);

    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    const char *const message = args->args[0];
    size_t messageLength = args->lengths[0];
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


/** sodium_box_seal_open(cipher, publicKey, secretKey) RETURNS STRING */
MYSQL_STRING_FUNCTION(sodium_box_seal_open,
{
    // init
    REQUIRE_ARGS(3);
    REQUIRE_STRING(0, cipher);
    REQUIRE_STRING(1, publicKey);
    REQUIRE_STRING(2, secretKey);

    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    const char *const cipher = args->args[0];
    size_t cipherLength = args->lengths[0];
    if (cipher == NULL) {
        return_MYSQL_NULL(NULL);
    }

    const char *const publicKey = args->args[1];
    if (args->lengths[1] != crypto_box_PUBLICKEYBYTES) {
        return_MYSQL_NULL(NULL);
    }

    const char *const secretKey = args->args[2];
    if (args->lengths[2] != crypto_box_SECRETKEYBYTES) {
        return_MYSQL_NULL(NULL);
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


/* sodium_box_secretkey(keyPair) RETURNS STRING */

SUBSTRING_FUNCTION(sodium_box_secretkey,
    keyPair, MYSQL_BINARY_STRING,
    crypto_box_PUBLICKEYBYTES, crypto_box_SECRETKEYBYTES,
    crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES
);


/* sodium_box_seed_keypair(seed) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_box_seed_keypair,
{
    // init
    REQUIRE_ARGS(1);
    REQUIRE_STRING(0, seed);

    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    char *const seed = args->args[0];
    if (args->lengths[0] != crypto_box_SEEDBYTES) {
        return_MYSQL_NULL(NULL);
    }

    result = fixed_buffer(result, crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES);

    MUST_SUCCEED(Sodium::crypto_box_seed_keypair(
        (unsigned char*)result,
        (unsigned char*)result + crypto_box_PUBLICKEYBYTES,
        (unsigned char*)seed
    ));

    return result;
}, {
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
});

