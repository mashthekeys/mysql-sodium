#include "sodium_udf.h"

/* sodium_secretbox(message, nonce, key) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_secretbox,
{
    // init
    REQUIRE_ARGS(3);
    REQUIRE_STRING(0, message);
    REQUIRE_STRING(1, nonce);
    REQUIRE_STRING(2, key);

    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    const char             *message = args->args[0];
    size_t                  messageLength = args->lengths[0];

    const char             *nonce = args->args[1];
    size_t                  nonceLength = args->lengths[1];

    const char             *key = args->args[2];
    size_t                  keyLength = args->lengths[2];

    if (message == NULL || nonceLength != crypto_secretbox_NONCEBYTES || keyLength != crypto_secretbox_KEYBYTES) {
        return_MYSQL_NULL(NULL);
    }

    result = fixed_buffer(result, messageLength + crypto_secretbox_MACBYTES);

    MUST_SUCCEED(Sodium::crypto_secretbox_easy(
        (unsigned char*)result,
        (unsigned char*)message, messageLength,
        (unsigned char*)nonce,
        (unsigned char*)key
    ));

    return result;
}, {
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
});


/* sodium_secretbox_keygen() RETURNS BINARY STRING */
BUFFER_GENERATOR_FUNCTION(
    sodium_secretbox_keygen,
    Sodium::crypto_secretbox_keygen,
    crypto_secretbox_KEYBYTES,
    MYSQL_BINARY_STRING
);


/* sodium_secretbox_open(cipher, nonce, key) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_secretbox_open,
{
    // init
    REQUIRE_ARGS(3);
    REQUIRE_STRING(0, cipher);
    REQUIRE_STRING(1, nonce);
    REQUIRE_STRING(2, key);

    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    const char             *cipher = args->args[0];
    size_t                  cipherLength = args->lengths[0];

    const char             *nonce = args->args[1];
    size_t                  nonceLength = args->lengths[1];

    const char             *key = args->args[2];
    size_t                  keyLength = args->lengths[2];

    if (cipher == NULL || nonceLength != crypto_secretbox_NONCEBYTES || keyLength != crypto_secretbox_KEYBYTES) {
        return_MYSQL_NULL(NULL);
    }

    result = fixed_buffer(result, cipherLength);

    MUST_SUCCEED(Sodium::crypto_secretbox_open_easy(
        (unsigned char*)result,
        (unsigned char*)cipher, cipherLength,
        (unsigned char*)nonce,
        (unsigned char*)key
    ));

    return result;
}, {
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
});