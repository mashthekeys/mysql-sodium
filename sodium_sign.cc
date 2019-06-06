#include "sodium_udf.h"

/* sodium_sign(detached, message, secretKey) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_sign,
{
    // init
    REQUIRE_ARGS(3);
    REQUIRE_CONST_INTEGER(0, detached);
    REQUIRE_STRING(1, message);
    REQUIRE_STRING(2, secretKey);

    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    const long long     detached = *(long long*)(args->args[0]);

    const char *const   message = args->args[1];
    const size_t        messageLength = args->lengths[1];

    const char *const   secretKey = args->args[2];
    const size_t        secretKeyLength = args->lengths[2];

    if (message == NULL || secretKeyLength != crypto_sign_SECRETKEYBYTES) {
        return_MYSQL_NULL(NULL);
    }

    if (detached == 0) {
        result = fixed_buffer(result, messageLength + crypto_sign_BYTES);

        MUST_SUCCEED(Sodium::crypto_sign(
            (unsigned char*)result, NULL,
            (unsigned char*)message, messageLength,
            (unsigned char*)secretKey)
        );
    } else {
        result = fixed_buffer(result, crypto_sign_BYTES);

        MUST_SUCCEED(Sodium::crypto_sign_detached(
            (unsigned char*)result, NULL,
            (unsigned char*)message, messageLength,
            (unsigned char*)secretKey)
        );
    }

    return result;
}, {
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
});


/* sodium_sign_keypair() RETURNS BINARY STRING */
/* sodium_sign_keypair(seed) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_sign_keypair,
{
    // init
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
    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    result = fixed_buffer(result, crypto_sign_PUBLICKEYBYTES + crypto_sign_SECRETKEYBYTES + 1);
    result[crypto_sign_PUBLICKEYBYTES] = BOUNDARY;

    if (args->arg_count) {
        // sodium_sign_keypair(seed)
        const char             *seed = args->args[0];
        size_t                  seedLength = args->lengths[0];

        if (seedLength != crypto_sign_SEEDBYTES) {
            return_MYSQL_NULL(NULL);
        }

        MUST_SUCCEED(Sodium::crypto_sign_seed_keypair(
            (unsigned char*)result,
            (unsigned char*)result + crypto_sign_PUBLICKEYBYTES + 1,
            (unsigned char*)seed
        ));
    } else {
        // sodium_sign_keypair()
        MUST_SUCCEED(Sodium::crypto_sign_keypair(
            (unsigned char*)result,
            (unsigned char*)result + crypto_sign_PUBLICKEYBYTES + 1
        ));
    }
    return result;
}, {
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
});




/* sodium_sign_open(signedMessage, publicKey) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_sign_open,
{
    // init
    REQUIRE_ARGS(2);
    REQUIRE_STRING(0, signedMessage);
    REQUIRE_STRING(1, publicKey);

    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    const char *const   signedMessage = args->args[0];
    const size_t        signedMessageLength = args->lengths[0];

    const char *const   publicKey = args->args[1];
    const size_t        publicKeyLength = args->lengths[1];

    if (signedMessage == NULL || publicKeyLength != crypto_sign_PUBLICKEYBYTES) {
        return_MYSQL_NULL(NULL);
    }

    result = dynamic_buffer(result, signedMessageLength, &(initid->ptr));

    unsigned long long resultLength;

    if (Sodium::crypto_sign(
        (unsigned char*)result, &resultLength,
        (unsigned char*)signedMessage, signedMessageLength,
        (unsigned char*)publicKey
    ) != SUCCESS) {
        return_MYSQL_NULL(NULL);
    }

    *length = (unsigned long)resultLength;

    return result;
}, {
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
});



/* sodium_sign_pk(keyPair) RETURNS BINARY STRING */
/* sodium_sign_publickey(keyPair) RETURNS BINARY STRING */
SUBSTRING_FUNCTION(sodium_sign_pk,
    keyPair,
    MYSQL_BINARY_STRING,
    0, crypto_sign_PUBLICKEYBYTES,
    crypto_sign_PUBLICKEYBYTES,
    crypto_sign_PUBLICKEYBYTES + crypto_sign_SECRETKEYBYTES + 1
);

UDF_STRING_ALIAS(sodium_sign_publickey, sodium_sign_pk);


/* sodium_sign_sk2pk(secretKey) RETURNS BINARY STRING */
/* sodium_sign_publickey_from_secretkey(secretKey) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_sign_sk2pk,
{
    // init
    REQUIRE_ARGS(1);
    REQUIRE_STRING(0, secretKey);
    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    const char * const  secretKey = args->args[0];
    const size_t        secretKeyLength = args->lengths[0];

    if (secretKeyLength != crypto_sign_SECRETKEYBYTES) {
        return_MYSQL_NULL(NULL);
    }

    result = fixed_buffer(result, crypto_sign_PUBLICKEYBYTES);

    MUST_SUCCEED(Sodium::crypto_sign_ed25519_sk_to_pk((unsigned char*)result, (unsigned char*)secretKey));

    return result;
}, {
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
});

UDF_STRING_ALIAS(sodium_sign_publickey_from_secretkey, sodium_sign_sk2pk);


/* sodium_sign_sk(keyPair) RETURNS BINARY STRING */
/* sodium_sign_secretkey(keyPair) RETURNS BINARY STRING */
SUBSTRING_FUNCTION(sodium_sign_sk,
    keyPair,
    MYSQL_BINARY_STRING,
    crypto_sign_PUBLICKEYBYTES + 1, crypto_sign_SECRETKEYBYTES,
    crypto_sign_PUBLICKEYBYTES,
    crypto_sign_PUBLICKEYBYTES + crypto_sign_SECRETKEYBYTES + 1
);

UDF_STRING_ALIAS(sodium_sign_secretkey, sodium_sign_sk);


/* sodium_sign_verify(signedMessage, publicKey) RETURNS INTEGER */
/* sodium_sign_verify(signature, message, publicKey) RETURNS INTEGER */
MYSQL_INTEGER_FUNCTION(sodium_sign_verify,
{
    // init
    switch (args->arg_count) {
        case 2:
            REQUIRE_STRING(0, signedMessage);
            REQUIRE_STRING(1, publicKey);
            break;
        case 3:
            REQUIRE_STRING(0, signature);
            REQUIRE_STRING(1, message);
            REQUIRE_STRING(2, publicKey);
            break;
        default:
            strcpy(message, "2-3 arguments required");
            return 1;
    }
}, {
    // main
    const char *    signature;
    size_t          signatureLength;
    const char *    message;
    size_t          messageLength;
    const char *    publicKey;
    size_t          publicKeyLength;

    if (args->arg_count >= 3) {
        // Syntax sodium_sign_verify(signature, message, publicKey)
        signature = args->args[0];
        signatureLength = args->lengths[0];

        message = args->args[1];
        messageLength = args->lengths[1];

        publicKey = args->args[2];
        publicKeyLength = args->lengths[2];
    } else {
        // Syntax sodium_sign_verify(signedMessage, publicKey)
        if (args->lengths[0] < crypto_sign_BYTES) return FAIL;

        signature = args->args[0];
        signatureLength = crypto_sign_BYTES;

        message = args->args[0] + crypto_sign_BYTES;
        messageLength = args->lengths[0] - crypto_sign_BYTES;

        publicKey = args->args[1];
        publicKeyLength = args->lengths[1];
    }

    if (message == NULL
        || signatureLength != crypto_sign_BYTES
        || publicKeyLength != crypto_sign_PUBLICKEYBYTES
    ) {
        return FAIL;
    }

    return Sodium::crypto_sign_verify_detached(
        (unsigned char*)signature,
        (unsigned char*)message, messageLength,
        (unsigned char*)publicKey
    );
}, {
    // deinit
});

UDF_INTEGER_ALIAS(sodium_sign_verify_detached, sodium_sign_verify);