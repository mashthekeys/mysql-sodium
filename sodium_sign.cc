#include "sodium_udf.h"

/* sodium_sign(message, secretKey) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_sign,
{
    // init
    REQUIRE_ARGS(2);
    REQUIRE_STRING(0, message);
    REQUIRE_STRING(1, secretKey);

    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    const char             *message = args->args[0];
    size_t                  messageLength = args->lengths[0];

    const char             *secretKey = args->args[1];
    size_t                  secretKeyLength = args->lengths[1];

    if (message == NULL || secretKeyLength != crypto_sign_SECRETKEYBYTES) {
        return_MYSQL_NULL(NULL);
    }

    result = fixed_buffer(result, messageLength + crypto_sign_BYTES);

    MUST_SUCCEED(Sodium::crypto_sign((unsigned char*)result, NULL, (unsigned char*)message, messageLength, (unsigned char*)secretKey));

    return result;
}, {
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
});


/* sodium_sign_detached(message, secretKey) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_sign_detached,
{
    // init
    REQUIRE_ARGS(2);
    REQUIRE_STRING(0, message);
    REQUIRE_STRING(1, secretKey);
}, {
    // main
    const char             *message = args->args[0];
    size_t                  messageLength = args->lengths[0];

    const char             *secretKey = args->args[1];
    size_t                  secretKeyLength = args->lengths[1];

    if (message == NULL || secretKeyLength != crypto_sign_SECRETKEYBYTES) {
        return_MYSQL_NULL(NULL);
    }

    result = fixed_buffer(result, crypto_sign_BYTES);

    MUST_SUCCEED(Sodium::crypto_sign_detached((unsigned char*)result, NULL, (unsigned char*)message, messageLength, (unsigned char*)secretKey));

    return result;
}, {
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
});


/* sodium_sign_keypair() RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_sign_keypair,
{
    // init
    REQUIRE_ARGS(0);
    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    result = fixed_buffer(result, crypto_sign_PUBLICKEYBYTES + crypto_sign_SECRETKEYBYTES);
    MUST_SUCCEED(Sodium::crypto_sign_keypair((unsigned char*)result, (unsigned char*)result + crypto_sign_PUBLICKEYBYTES));
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
    const char             *signedMessage = args->args[0];
    size_t                  signedMessageLength = args->lengths[0];

    const char             *publicKey = args->args[1];
    size_t                  publicKeyLength = args->lengths[1];

    if (signedMessage == NULL || publicKeyLength != crypto_sign_PUBLICKEYBYTES) {
        return_MYSQL_NULL(NULL);
    }

    result = dynamic_buffer(result, signedMessageLength, &(initid->ptr));

    unsigned long long messageLength;

    if (Sodium::crypto_sign((unsigned char*)result, &messageLength, (unsigned char*)signedMessage, signedMessageLength, (unsigned char*)publicKey) != SUCCESS) {
        return_MYSQL_NULL(NULL);
    }

    *length = (unsigned long)messageLength;

    return result;
}, {
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
});



/* sodium_sign_publickey(keyPair) RETURNS BINARY STRING */
SUBSTRING_FUNCTION(sodium_sign_publickey, keyPair, MYSQL_BINARY_STRING, 0, crypto_sign_PUBLICKEYBYTES, crypto_sign_PUBLICKEYBYTES + crypto_sign_SECRETKEYBYTES);


/* sodium_sign_publickey_from_secretkey(secretKey) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_sign_publickey_from_secretkey,
{
    // init
    REQUIRE_ARGS(1);
    REQUIRE_STRING(0, secretKey);
    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    const char *secretKey = args->args[0];
    size_t      secretKeyLength = args->lengths[0];

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


/* sodium_sign_secretkey(keyPair) RETURNS BINARY STRING */
SUBSTRING_FUNCTION(sodium_sign_secretkey, keyPair, MYSQL_BINARY_STRING, crypto_sign_PUBLICKEYBYTES, crypto_sign_SECRETKEYBYTES, crypto_sign_PUBLICKEYBYTES + crypto_sign_SECRETKEYBYTES);


/* sodium_sign_seed_keypair(seed) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_sign_seed_keypair,
{
    // init
    REQUIRE_ARGS(1);
    REQUIRE_STRING(0, seed);
    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    const char             *seed = args->args[0];
    size_t                  seedLength = args->lengths[0];

    if (seedLength != crypto_sign_SEEDBYTES) {
        return_MYSQL_NULL(NULL);
    }

    result = fixed_buffer(result, crypto_sign_PUBLICKEYBYTES + crypto_sign_SECRETKEYBYTES);
    MUST_SUCCEED(Sodium::crypto_sign_seed_keypair((unsigned char*)result, (unsigned char*)result + crypto_sign_PUBLICKEYBYTES, (unsigned char*)seed));
    return result;
}, {
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
});


/* sodium_sign_verify_detached(signature, message, publicKey) RETURNS INTEGER */
MYSQL_INTEGER_FUNCTION(sodium_sign_verify_detached,
{
    // init
    REQUIRE_ARGS(3);
    REQUIRE_STRING(0, signature);
    REQUIRE_STRING(1, message);
    REQUIRE_STRING(2, publicKey);
}, {
    // main
    const char             *signature = args->args[0];
    size_t                  signatureLength = args->lengths[0];

    const char             *message = args->args[1];
    size_t                  messageLength = args->lengths[1];

    const char             *publicKey = args->args[2];
    size_t                  publicKeyLength = args->lengths[2];

    if (message == NULL
        || signatureLength != crypto_sign_BYTES
        || publicKeyLength != crypto_sign_PUBLICKEYBYTES
     ) {
        return FAIL;
    }

    return Sodium::crypto_sign_verify_detached((unsigned char*)signature, (unsigned char*)message, messageLength, (unsigned char*)publicKey);
}, {
    // deinit
});
