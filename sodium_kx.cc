#include "sodium_udf.h"

/* sodium_kx_client_session_keys(clientPublicKey, clientSecretKey, serverPublicKey) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_kx_client_session_keys,
{
    // init
    REQUIRE_ARGS(3);
    REQUIRE_STRING(0, clientPublicKey);
    REQUIRE_STRING(1, clientSecretKey);
    REQUIRE_STRING(2, serverPublicKey);

    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    size_t clientPublicKeyLength = args->lengths[0];
    size_t clientSecretKeyLength = args->lengths[1];
    size_t serverPublicKeyLength = args->lengths[2];
    if (clientPublicKeyLength != crypto_kx_PUBLICKEYBYTES
        || clientSecretKeyLength != crypto_kx_SECRETKEYBYTES
        || serverPublicKeyLength != crypto_kx_PUBLICKEYBYTES
    ) {
        return MYSQL_NULL;
    }
    const char *const clientPublicKey = args->args[0];
    const char *const clientSecretKey = args->args[1];
    const char *const serverPublicKey = args->args[2];

    result = fixed_buffer(result, crypto_kx_SESSIONKEYBYTES * 2, initid->ptr);

    MUST_SUCCEED(Sodium::crypto_kx_client_session_keys(
        result, result + crypto_kx_SESSIONKEYBYTES,
        clientPublicKey, clientSecretKey, serverPublicKey
    ));

    return result;
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
});


/* sodium_kx_keypair() RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_kx_keypair,
{
    // init
    REQUIRE_ARGS(0);
    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    result = fixed_buffer(result, crypto_kx_PUBLICKEYBYTES + crypto_kx_SECRETKEYBYTES, initid->ptr);
    MUST_SUCCEED(Sodium::crypto_kx_keypair(result, result + crypto_kx_PUBLICKEYBYTES));
    return result;
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
});


/* sodium_kx_publickey(keyPair) RETURNS BINARY STRING */
SUBSTRING_FUNCTION(sodium_kx_publickey,
    keyPair, MYSQL_BINARY_STRING,
    0, crypto_kx_PUBLICKEYBYTES,
    crypto_kx_PUBLICKEYBYTES + crypto_kx_SECRETKEYBYTES
);

/* sodium_kx_secretkey(keyPair) RETURNS BINARY STRING */
SUBSTRING_FUNCTION(sodium_kx_secretkey,
    keyPair, MYSQL_BINARY_STRING,
    crypto_kx_PUBLICKEYBYTES, crypto_kx_SECRETKEYBYTES,
    crypto_kx_PUBLICKEYBYTES + crypto_kx_SECRETKEYBYTES
);


/* sodium_kx_seed_keypair(seed) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_kx_seed_keypair,
{
    // init
    REQUIRE_ARGS(1);
    REQUIRE_STRING(0, seed);
    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    const char *const seed = args->args[0];
    if (args->lengths[0] != crypto_kx_SEEDBYTES) {
        return MYSQL_NULL;
    }

    result = fixed_buffer(result, crypto_kx_PUBLICKEYBYTES + crypto_kx_SECRETKEYBYTES, initid->ptr);

    MUST_SUCCEED(Sodium::crypto_kx_seed_keypair(result, result + crypto_kx_PUBLICKEYBYTES, seed));

    return result;
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
});


/* sodium_kx_server_session_keys(serverPublicKey, serverSecretKey, clientPublicKey) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_kx_server_session_keys,
{
    // init
    REQUIRE_ARGS(3);
    REQUIRE_STRING(0, serverPublicKey);
    REQUIRE_STRING(1, serverSecretKey);
    REQUIRE_STRING(2, clientPublicKey);

    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    size_t serverPublicKeyLength = args->lengths[0];
    size_t serverSecretKeyLength = args->lengths[1];
    size_t clientPublicKeyLength = args->lengths[2];
    if (clientPublicKeyLength != crypto_kx_PUBLICKEYBYTES
        || serverSecretKeyLength != crypto_kx_SECRETKEYBYTES
        || serverPublicKeyLength != crypto_kx_PUBLICKEYBYTES
    ) {
        return MYSQL_NULL;
    }

    const char *const serverPublicKey = args->args[0];
    const char *const serverSecretKey = args->args[1];
    const char *const clientPublicKey = args->args[2];

    result = fixed_buffer(result, crypto_kx_SESSIONKEYBYTES + crypto_kx_SESSIONKEYBYTES, initid->ptr);

    MUST_SUCCEED(Sodium::crypto_kx_server_session_keys(
        result, result + crypto_kx_SESSIONKEYBYTES,
        serverPublicKey, serverSecretKey, clientPublicKey
    ));

    return result;
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
});

