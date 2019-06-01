#include "sodium_udf.h"

/* sodium_generichash(hashLength?, message, key?) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_generichash,
{
    // init
    switch (args->arg_count) {
        case 3: {
            // sodium_generichash(hashLength?, message, key)
            if (args->args[2] != NULL) REQUIRE_STRING(2);
        }
        // fall through to check args 0 and 1
        case 2: {
            // sodium_generichash(hashLength?, message)
            if (args->args[0] != NULL) REQUIRE_CONST_INTEGER(0);
            REQUIRE_STRING(1);
        }
        break;
        default: {
            strcpy(message, "2 or 3 arguments required");
            return 1;
    }
    }

    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    const long long hashLength = args->args[0] == NULL
        ? crypto_generichash_BYTES
        : *((long long *)args->args[0]);

    const char *const message = args->args[1];
    size_t messageLength = args->lengths[1];
    if (message == NULL) {
        return MYSQL_NULL;
    }

    size_t keyLength = args->lengths[2];
    const char *const key = (args->arg_count > 2 && keyLength != 0)
        ? args->args[2]
        : NULL;
    if (key != NULL
        && (keyLength < crypto_generichash_KEYBYTES_MIN
            || keyLength > crypto_generichash_KEYBYTES_MAX)
    ) {
        return MYSQL_NULL;
    }

    result = fixed_buffer(result, hashLength);

    MUST_SUCCEED(Sodium::crypto_generichash(hashLength, message, messageLength, key, keyLength));

    return result;
}, {
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
});



/* sodium_generichash_keygen() RETURNS BINARY STRING */
BUFFER_GENERATOR_FUNCTION(
    sodium_generichash_keygen,
    crypto_generichash_keygen,
    crypto_generichash_KEYBYTES,
    MYSQL_BINARY_STRING
);


/* sodium_shorthash(input, key) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_shorthash,
{
    // init
    REQUIRE_ARGS(2);
    REQUIRE_STRING(0, input);
    REQUIRE_STRING(1, key);

    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    const char             *input = args->args[0];
    size_t                  inputLength = args->lengths[0];

    const char             *key = args->args[1];
    size_t                  keyLength = args->lengths[1];

    if (input == NULL || keyLength != crypto_shorthash_KEYBYTES) {
        return MYSQL_NULL;
    }

    if (Sodium::crypto_shorthash(result, message, messageLength, key) != SUCCESS) {
        return MYSQL_NULL;
    }

    *length = (unsigned long)messageLength;

    return result;

}, {
    // deinit
});


/* sodium_shorthash_keygen() RETURNS BINARY STRING */
BUFFER_GENERATOR_FUNCTION(
    sodium_shorthash_keygen,
    crypto_shorthash_keygen,
    crypto_shorthash_KEYBYTES,
    MYSQL_BINARY_STRING
);
