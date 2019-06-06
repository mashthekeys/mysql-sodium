#include "sodium_udf.h"

/** SODIUM_KX_CLIENT_SESSION_KEYS(clientPublicKey, clientSecretKey, serverPublicKey)
 *  RETURNS VARBINARY
 *
 *  Generate a client-side keypair for key exchange.
 *
 * @CREATE FUNCTION sodium_kx_client_session_keys RETURNS STRING
 */
MYSQL_STRING_FUNCTION(sodium_kx_client_session_keys,
{
    // init
    initid->maybe_null = 1;
    initid->max_length = MYSQL_BINARY_STRING;

    REQUIRE_ARGS(3);
    REQUIRE_STRING(0, clientPublicKey);
    REQUIRE_STRING(1, clientSecretKey);
    REQUIRE_STRING(2, serverPublicKey);
}, {
    // main
    size_t clientPublicKeyLength = args->lengths[0];
    size_t clientSecretKeyLength = args->lengths[1];
    size_t serverPublicKeyLength = args->lengths[2];
    if (clientPublicKeyLength != crypto_kx_PUBLICKEYBYTES
        || clientSecretKeyLength != crypto_kx_SECRETKEYBYTES
        || serverPublicKeyLength != crypto_kx_PUBLICKEYBYTES
    ) {
        return_MYSQL_NULL(NULL);
    }
    const char *const clientPublicKey = args->args[0];
    const char *const clientSecretKey = args->args[1];
    const char *const serverPublicKey = args->args[2];

    result = fixed_buffer(result, 1 + crypto_kx_SESSIONKEYBYTES * 2);
    result[crypto_kx_SESSIONKEYBYTES] = BOUNDARY;

    MUST_SUCCEED(Sodium::crypto_kx_client_session_keys(
        (unsigned char*)result, (unsigned char*)result + crypto_kx_SESSIONKEYBYTES + 1,
        (unsigned char*)clientPublicKey, (unsigned char*)clientSecretKey, (unsigned char*)serverPublicKey
    ));

    return result;
}, {
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
});


/** SODIUM_KX_KEYPAIR() RETURNS VARBINARY
 *
 *  Creates a new keypair for key exchange.
 *
 *  SODIUM_KX_KEYPAIR(seed) RETURNS VARBINARY
 *
 *  Deterministically computes a new keypair for key exchange.
 *
 * @CREATE FUNCTION sodium_kx_keypair RETURNS STRING
 */
MYSQL_STRING_FUNCTION(sodium_kx_keypair,
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
    result = fixed_buffer(result, crypto_kx_PUBLICKEYBYTES + crypto_kx_SECRETKEYBYTES + 1);
    result[crypto_kx_PUBLICKEYBYTES] = BOUNDARY;

    if (args->arg_count) {
        // Syntax sodium_kx_keypair(seed)
        const char *const seed = args->args[0];
        if (args->lengths[0] != crypto_kx_SEEDBYTES) {
            return_MYSQL_NULL(NULL);
        }

        MUST_SUCCEED(Sodium::crypto_kx_seed_keypair(
            (unsigned char*)result,
            (unsigned char*)result + crypto_kx_PUBLICKEYBYTES + 1,
            (unsigned char*)seed
        ));
    } else {
        // Syntax sodium_kx_keypair()
        MUST_SUCCEED(Sodium::crypto_kx_keypair(
            (unsigned char*)result,
            (unsigned char*)result + crypto_kx_PUBLICKEYBYTES + 1
        ));
    }
    return result;
}, {
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
});


/** sodium_kx_pk(keyPair) RETURNS BINARY(crypto_kx_SECRETKEYBYTES)
 *
 * Extract secret key from a keypair.
 *
 * @CREATE FUNCTION sodium_kx_pk RETURNS STRING
 * @ALIAS FUNCTION sodium_kx_publickey RETURNS STRING
 */
SUBSTRING_FUNCTION(sodium_kx_pk,
    keyPair, MYSQL_BINARY_STRING,
    0, crypto_kx_PUBLICKEYBYTES,
    crypto_kx_PUBLICKEYBYTES,
    crypto_kx_PUBLICKEYBYTES + crypto_kx_SECRETKEYBYTES + 1
);

UDF_STRING_ALIAS(sodium_kx_publickey, sodium_kx_pk);

/** sodium_kx_sk(keyPair) RETURNS BINARY(crypto_kx_SECRETKEYBYTES)
 *
 * Extract secret key from a keypair.
 *
 * @CREATE FUNCTION sodium_kx_sk RETURNS STRING
 * @ALIAS FUNCTION sodium_kx_secretkey RETURNS STRING
 */
SUBSTRING_FUNCTION(sodium_kx_sk,
    keyPair, MYSQL_BINARY_STRING,
    crypto_kx_PUBLICKEYBYTES + 1, crypto_kx_SECRETKEYBYTES,
    crypto_kx_PUBLICKEYBYTES,
    crypto_kx_PUBLICKEYBYTES + crypto_kx_SECRETKEYBYTES + 1
);

UDF_STRING_ALIAS(sodium_kx_secretkey, sodium_kx_sk);


/** SODIUM_KX_SERVER_SESSION_KEYS(serverPublicKey, serverSecretKey, clientPublicKey)
 *  RETURNS VARBINARY
 *
 *  Generate a server-side keypair for key exchange.
 *
 * @CREATE FUNCTION sodium_kx_server_session_keys RETURNS STRING
 */
MYSQL_STRING_FUNCTION(sodium_kx_server_session_keys,
{
    // init
    initid->maybe_null = 1;
    initid->max_length = MYSQL_BINARY_STRING;

    REQUIRE_ARGS(3);
    REQUIRE_STRING(0, serverPublicKey);
    REQUIRE_STRING(1, serverSecretKey);
    REQUIRE_STRING(2, clientPublicKey);
}, {
    // main
    size_t serverPublicKeyLength = args->lengths[0];
    size_t serverSecretKeyLength = args->lengths[1];
    size_t clientPublicKeyLength = args->lengths[2];
    if (clientPublicKeyLength != crypto_kx_PUBLICKEYBYTES
        || serverSecretKeyLength != crypto_kx_SECRETKEYBYTES
        || serverPublicKeyLength != crypto_kx_PUBLICKEYBYTES
    ) {
        return_MYSQL_NULL(NULL);
    }

    const char *const serverPublicKey = args->args[0];
    const char *const serverSecretKey = args->args[1];
    const char *const clientPublicKey = args->args[2];

    result = fixed_buffer(result, crypto_kx_SESSIONKEYBYTES + crypto_kx_SESSIONKEYBYTES + 1);
    result[crypto_kx_SESSIONKEYBYTES] = BOUNDARY;

    MUST_SUCCEED(Sodium::crypto_kx_server_session_keys(
        (unsigned char*)result, (unsigned char*)result + crypto_kx_SESSIONKEYBYTES + 1,
        (unsigned char*)serverPublicKey, (unsigned char*)serverSecretKey, (unsigned char*)clientPublicKey
    ));

    return result;
}, {
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
});

