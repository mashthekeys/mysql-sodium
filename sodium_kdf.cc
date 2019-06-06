#include "sodium_udf.h"

/** SODIUM_KDF(keyLength, subkeyID, context, masterKey) RETURNS VARBINARY
 *
 *  Derive a subkey from an existing key.
 *
 * @CREATE FUNCTION sodium_kdf() RETURNS STRING
 * @ALIAS FUNCTION sodium_kdf_derive_from_key() RETURNS STRING
 */
MYSQL_STRING_FUNCTION(sodium_kdf,
{
    // init
    initid->maybe_null = 1;
    initid->max_length = MYSQL_BINARY_STRING;

    REQUIRE_ARGS(4);
    REQUIRE_CONST_INTEGER(0, keyLength);
    REQUIRE_INTEGER(1, subkeyID);
    REQUIRE_STRING(2, context);
    REQUIRE_STRING(3, masterKey);
}, {
    // main
    const long long keyLength = *((long long *)args->args[0]);
    if (crypto_kdf_BYTES_MIN < keyLength || crypto_kdf_BYTES_MAX > keyLength) {
        return_MYSQL_NULL(NULL);
    }

    if (args->args[1] == NULL) return_MYSQL_NULL(NULL);
    const unsigned long long subkeyID = *((unsigned long long *)args->args[1]);

    const char *const context = args->args[2];
    size_t contextLength = args->lengths[2];
    if (contextLength != crypto_kdf_CONTEXTBYTES) {
        return_MYSQL_NULL(NULL);
    }

    const char *const masterKey = args->args[3];
    size_t masterKeyLength = args->lengths[3];
    if (masterKeyLength != crypto_kdf_KEYBYTES) {
        return_MYSQL_NULL(NULL);
    }

    result = fixed_buffer(result, keyLength);

    MUST_SUCCEED(Sodium::crypto_kdf_derive_from_key(
        (unsigned char*)result, keyLength,
        subkeyID,
        context,
        (unsigned char*)masterKey
    ));

    return result;
}, {
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
});

UDF_STRING_ALIAS(sodium_kdf_derive_from_key, sodium_kdf);


/** SODIUM_KDF_KEYGEN() RETURNS BINARY(crypto_kdf_KEYBYTES)
 *
 *  Randomly generate a key for SODIUM_KDF.
 *
 * @CREATE FUNCTION sodium_kdf_keygen() RETURNS STRING */
BUFFER_GENERATOR_FUNCTION(
    sodium_kdf_keygen,
    Sodium::crypto_kdf_keygen,
    crypto_kdf_KEYBYTES,
    MYSQL_BINARY_STRING
);


