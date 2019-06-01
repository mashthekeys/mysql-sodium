#include "sodium_udf.h"

/** sodium_auth(message, key) RETURNS STRING */
MYSQL_STRING_FUNCTION(sodium_auth,
{
    // init
    REQUIRE_ARGS(2);
    REQUIRE_STRING(0, message);
    REQUIRE_STRING(1, key);

    initid->max_length = MYSQL_BINARY_STRING;
},
{
    // main
    const char *const message = args->args[0];
    size_t messageLength = args->lengths[0];

    if (message == NULL) {
        return MYSQL_NULL;
    }

    if (args->lengths[1] != crypto_auth_KEYBYTES) {
        return MYSQL_NULL;
    }
    result = fixed_buffer(result, crypto_auth_BYTES);

    MUST_SUCCEED(Sodium::crypto_auth(result, message, messageLength, key));

    return result;
},
{
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
}
);


/* sodium_auth_keygen() RETURNS BINARY STRING */
BUFFER_GENERATOR_FUNCTION(
    sodium_auth_keygen,
    crypto_auth_keygen,
    crypto_auth_KEYBYTES,
    MYSQL_BINARY_STRING
);


/** sodium_auth_verify(mac, message, key) RETURNS INTEGER */
MYSQL_INTEGER_FUNCTION(sodium_auth_verify,
{
    // init
    REQUIRE_ARGS(3);
    REQUIRE_STRING(0, mac);
    REQUIRE_STRING(1, message);
    REQUIRE_STRING(2, key);
}, {
    // main
    const char *const mac = args->args[0];
    if (args->lengths[0] != crypto_auth_BYTES) {
        return FAIL;
    }

    const char *const message = args->args[1];
    size_t messageLength = args->lengths[1];
    if (message == NULL) {
        return FAIL;
    }

    if (args->lengths[2] != crypto_auth_KEYBYTES) {
        return FAIL;
    }
    const char *const key = args->args[2];

    return Sodium::crypto_auth_verify(mac, message, messageLength, key);
}, {
    // deinit
});


