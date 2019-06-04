#include "sodium_udf.h"

/** sodium_box(message, nonce, publicKey, secretKey) RETURNS STRING */
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


/** sodium_box_keypair() RETURNS BINARY STRING
 *
 *  sodium_box_keypair(seed) RETURNS BINARY STRING
 *
 * @CREATE FUNCTION sodium_box_keypair() RETURNS STRING
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


/** sodium_box_open(cipher, nonce, publicKey, secretKey) RETURNS STRING */
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


/* sodium_box_pk(keyPair) RETURNS BINARY STRING */
/* ALIAS sodium_box_publickey(keyPair) RETURNS BINARY STRING */
SUBSTRING_FUNCTION(sodium_box_pk,
    keyPair, MYSQL_BINARY_STRING,
    0, crypto_box_PUBLICKEYBYTES,
    crypto_box_PUBLICKEYBYTES,
    crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES + 1
);

UDF_STRING_ALIAS(sodium_box_publickey, sodium_box_pk);

/* sodium_box_sk2pk(secretKey) RETURNS BINARY STRING */
/* ALIAS sodium_box_publickey_from_secretkey(secretKey) RETURNS BINARY STRING */
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


/** sodium_box_seal(message, publicKey) RETURNS STRING */
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


/** sodium_box_seal_open(cipher, publicKey, secretKey) RETURNS STRING */
MYSQL_STRING_FUNCTION(sodium_box_seal_open,
{
    // init
    initid->maybe_null = 1;
    initid->max_length = MYSQL_BINARY_STRING;

    REQUIRE_ARGS(3);
    REQUIRE_STRING(0, cipher);
    REQUIRE_STRING(1, publicKey);
    REQUIRE_STRING(2, secretKey);
}, {
    // main
    const char *const   cipher = args->args[0];
    const size_t        cipherLength = args->lengths[0];
    if (cipher == NULL) {
        return_MYSQL_NULL(NULL);
    }

    const char *const   publicKey = args->args[1];
    if (args->lengths[1] != crypto_box_PUBLICKEYBYTES) {
        return_MYSQL_NULL(NULL);
    }

    const char *const   secretKey = args->args[2];
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


/* sodium_box_sk(keyPair) RETURNS STRING */
/* ALIAS sodium_box_secretkey(keyPair) RETURNS STRING */
SUBSTRING_FUNCTION(sodium_box_sk,
    keyPair, MYSQL_BINARY_STRING,
    crypto_box_PUBLICKEYBYTES + 1, crypto_box_SECRETKEYBYTES,
    crypto_box_PUBLICKEYBYTES,
    crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES + 1
);

UDF_STRING_ALIAS(sodium_box_secretkey, sodium_box_sk);

