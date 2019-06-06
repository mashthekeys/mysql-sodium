#include "sodium_udf.h"

/** SODIUM_AUTH(message, key) RETURNS BINARY(crypto_auth_BYTES)
 *
 *  Compute a verification tag for the message.
 *
 * @CREATE FUNCTION sodium_auth() RETURNS STRING
 */
MYSQL_STRING_FUNCTION(sodium_auth,
{
    // init
    initid->maybe_null = 1;
    initid->max_length = MYSQL_BINARY_STRING;

    REQUIRE_ARGS(2);
    REQUIRE_STRING(0, message);
    REQUIRE_STRING(1, key);
},
{
    // main
    const char *const message = args->args[0];
    size_t messageLength = args->lengths[0];

    if (message == NULL) {
        return_MYSQL_NULL(NULL);
    }

    const char *const key = args->args[1];
    size_t keyLength = args->lengths[1];

    if (keyLength != crypto_auth_KEYBYTES) {
        return_MYSQL_NULL(NULL);
    }
    result = fixed_buffer(result, crypto_auth_BYTES);

    MUST_SUCCEED(Sodium::crypto_auth(
        (unsigned char*)result,
        (unsigned char*)message, messageLength,
        (unsigned char*)key
    ));

    return result;
},
{
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
}
);


/** SODIUM_AUTH_KEYGEN() RETURNS BINARY(crypto_auth_KEYBYTES)
 *
 *  Generate a new key for use with SODIUM_AUTH.
 *
 * @CREATE FUNCTION sodium_auth_keygen() RETURNS STRING
 */
BUFFER_GENERATOR_FUNCTION(
    sodium_auth_keygen,
    Sodium::crypto_auth_keygen,
    crypto_auth_KEYBYTES,
    MYSQL_BINARY_STRING
);


/** SODIUM_AUTH_VERIFY(tag, message, key) RETURNS INTEGER
 *
 *  Verifies that the tag is valid for the message.
 *
 * @CREATE FUNCTION sodium_auth_verify() RETURNS INTEGER
 */
MYSQL_INTEGER_FUNCTION(sodium_auth_verify,
{
    // init
    REQUIRE_ARGS(3);
    REQUIRE_STRING(0, tag);
    REQUIRE_STRING(1, message);
    REQUIRE_STRING(2, key);
}, {
    // main
    const char *const tag = args->args[0];
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

    return Sodium::crypto_auth_verify(
        (unsigned char*)tag,
        (unsigned char*)message, messageLength,
        (unsigned char*)key
    );
}, {
    // deinit
});


