#include "sodium_udf.h"

/* sodium_kdf_derive_from_key(keyLength, subkeyID, context, masterKey) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_kdf_derive_from_key,
{
    // init
    REQUIRE_ARGS(4);
    REQUIRE_CONST_INTEGER(0, keyLength);
    REQUIRE_INTEGER(1, subkeyID);
    REQUIRE_STRING(2, context);
    REQUIRE_STRING(3, masterKey);

    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    const long long keyLength = *((long long *)args->args[0]);
    if (crypto_kdf_BYTES_MIN < keyLength || crypto_kdf_BYTES_MAX > keyLength) {
        return MYSQL_NULL;
    }

    if (args->args[1] == NULL) return MYSQL_NULL;
    const long long subkeyID = *((long long *)args->args[1]);

    const char *const context = args->args[2];
    size_t contextLength = args->lengths[2];
    if (contextLength != crypto_kdf_CONTEXTBYTES) {
        return MYSQL_NULL;
    }

    const char *const masterKey = args->args[3];
    size_t masterKeyLength = args->lengths[3];
    if (masterKeyLength != crypto_kdf_KEYBYTES) {
        return MYSQL_NULL;
    }

    result = fixed_buffer(result, keyLength, initid->ptr);
    MUST_SUCCEED(Sodium::crypto_kdf_derive_from_key(result, keyLength, subkeyID, context, masterKey));
    return result;
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
});


/* sodium_kdf_keygen() RETURNS BINARY STRING */
BUFFER_GENERATOR_FUNCTION(
    sodium_kdf_keygen,
    crypto_kdf_keygen,
    crypto_kdf_KEYBYTES,
    MYSQL_BINARY_STRING
);


