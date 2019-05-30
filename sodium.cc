/* Copyright (c) 2019 Andy Holland <github@ahweb.co.uk> Licence GPL */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <new>
#include <string>

#include "mysql_udf.h"

namespace Sodium {
  #include <sodium.h>
}

#define mysql_RESULT_LENGTH 255

#if crypto_pwhash_STRBYTES >= mysql_RESULT_LENGTH
    #error "crypto_pwhash_STRBYTES is too large: sodium_pwhash_str_init needs to be rewritten to use malloc"
#endif


struct security_level {
    const char               *name;
    const unsigned long long  opslimit;
    const size_t              memlimit;
};

const size_t            PWHASH_TYPES = 5;

const security_level    PWHASH_TYPE_LIST[PWHASH_TYPES] = {
    {"INTERACTIVE", crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE},
    {"MAX",         crypto_pwhash_OPSLIMIT_MAX,         crypto_pwhash_MEMLIMIT_MAX},
    {"MIN",         crypto_pwhash_OPSLIMIT_MIN,         crypto_pwhash_MEMLIMIT_MIN},
    {"MODERATE",    crypto_pwhash_OPSLIMIT_MODERATE,    crypto_pwhash_MEMLIMIT_MODERATE},
    {"SENSITIVE",   crypto_pwhash_OPSLIMIT_SENSITIVE,   crypto_pwhash_MEMLIMIT_SENSITIVE}
};

const security_level *pwhash_security_preset(securityLevel, securityLevelLength) {
    const security_level *matching_level = NULL;
    long long x;

    for (x = 0; x < PWHASH_TYPES; ++x) {
        const char *type = PWHASH_TYPE_LIST[x].name;
        size_t typeLength = strlen(type);

        if (securityLevelLength == typeLength
            && strncasecmp(type, securityLevel, typeLength) == 0
        ) {
            matching_level = PWHASH_TYPE_LIST + x;
            break;
        }
    }
}
const char *const pwhash_SECURITY_INVALID = "securityLevel must be INTERACTIVE, MODERATE, SENSITIVE, MAX, or MIN.";


#define fixed_buffer(preallocated, fixedLength, alloc_result) \
    dynamic_buffer(preallocated, fixedLength, alloc_result); \
    *length = fixedLength;

char *dynamic_buffer(char *preallocated, size_t required, char *alloc_result) {
    if (required < mysql_RESULT_LENGTH)  {
        return preallocated;
    }

    const char* buffer = malloc(required + 1);

    if (alloc_result != NULL) *alloc_result = buffer;

    return buffer;
}

#define MYSQL_NULL (*is_null = 1, 0)


#define SUCCESS 0
#define FAIL -1

#define MUST_SUCCEED(expression) {\
    if ((expression) != SUCCESS) {\
        *error = 1; // Sodium internal error\
        return 0;\
    }\
}

#define REQUIRE_ARGS(n) {\
    if (args->arg_count != n) {\
        strcpy(message, #n " arguments required");\
        return 1;\
    }\
}

#define REQUIRE_STRING(n, label)    {\
    if (args->arg_type[n] != STRING_RESULT) {\
        strcpy(message, #label " must be a string");\
        return 1;\
    }\
}

#define REQUIRE_INTEGER(n, label)   {\
    if (args->arg_type[n] != INTEGER_RESULT) {\
        strcpy(message, #label " must be an integer");\
        return 1;\
    }\
}

#define REQUIRE_DOUBLE(n, label)    {\
    if (args->arg_type[n] != DOUBLE_RESULT) {\
        strcpy(message, #label " must be a double");\
        return 1;\
    }\
}

#define REQUIRE_CONST_STRING(n, label)    {\
    if (args->arg_type[n] != STRING_RESULT || args->args[n] == NULL) {\
        strcpy(message, #label " must be a constant string");\
        return 1;\
    }\
}

#define REQUIRE_CONST_INTEGER(n, label)   {\
    if (args->arg_type[n] != INTEGER_RESULT || args->args[n] == NULL) {\
        strcpy(message, #label " must be a constant integer");\
        return 1;\
    }\
}

#define REQUIRE_CONST_DOUBLE(n, label)    {\
    if (args->arg_type[n] != DOUBLE_RESULT || args->args[n] == NULL) {\
        strcpy(message, #label " must be a constant double");\
        return 1;\
    }\
}

#define SUBSTRING_FUNCTION(substr_udf, substr_field, substr_max_length, substr_offset, substr_length, total_field_length) \
MYSQL_STRING_FUNCTION(substr_udf, \
{ \
    // init \
    REQUIRE_ARGS(1); \
    REQUIRE_STRING(0, substr_field); \
    initid->max_length = (substr_max_length); \
}, {\
    // main\
    const char *const substr_field = args->args[0];\
    if (substr_field == NULL || args->lengths[0] != (total_field_length)) {\
        return MYSQL_NULL;\
    }\
    result = fixed_buffer(result, (substr_length), initid->ptr);\
    strcpy(result, substr_field + (substr_offset), (substr_length));\
    return result;\
}, {\
    // deinit\
    if (initid->ptr != NULL)  free(initid->ptr);\
})


/**@FUNCTION sodium_pwhash_str(message, securityLevel) RETURNS STRING */
/**@FUNCTION sodium_pwhash_str(message, memoryLimit, operationLimit) RETURNS STRING */
MYSQL_STRING_FUNCTION(sodium_pwhash_str,
{ // init:
    REQUIRE_STRING(0, password);

    if (args->arg_count == 2) {
        REQUIRE_CONST_STRING(1, securityLevel);

        const security_level *const matching_level = pwhash_security_preset(args->args[1], args->lengths[1]);

        if (matching_level == NULL) {
            strcpy(message, pwhash_SECURITY_INVALID);
            return 1;
        } else {
            // Store security level in pointer for main function
            initid->ptr = (char *)matching_level;
        }

    } else if (args->arg_count == 3) {
        REQUIRE_CONST_INTEGER(1, memoryLimit);
        REQUIRE_CONST_INTEGER(2, operationLimit);

        const long long    memlimit = *((long long *)args->args[1]);
        const long long    opslimit = *((long long *)args->args[2]);
        if (memlimit < 0 || memlimit > SIZE_MAX) {
            strcpy(message, "memoryLimit is out of bounds");
            return 1;
        }
        if (opslimit < 0) {
            strcpy(message, "operationLimit is out of bounds");
            return 1;
        }

    } else {
        strcpy(message, "2-3 arguments required");
        return 1;
    }

    initid->maybe_null = 1;
    initid->max_length = crypto_pwhash_STRBYTES;

    return 0;
},
{ // main:
    const char             *passwd = args->args[0];
    size_t                  passwd_len = args->lengths[0];
    size_t                  memlimit;
    unsigned long long      opslimit;
    const security_level   *ptr;

    if (initid->ptr != NULL) {
        ptr = (security_level *)(initid->ptr);

        memlimit = ptr->memlimit;
        opslimit = ptr->opslimit;

    } else {
        memlimit = args->args[1] ? *((unsigned long long *)args->args[1]) : 0;
        opslimit = args->args[2] ? (size_t)*((long long *)args->args[2]) : 0;
    }


    if (passwd == NULL || passwd_len <= 0 || passwd_len >= 0xffffffff) {
        return MYSQL_NULL;
    }

    if (opslimit < crypto_pwhash_OPSLIMIT_MIN) {
        opslimit = crypto_pwhash_OPSLIMIT_MIN;
    }

    if (memlimit < crypto_pwhash_MEMLIMIT_MIN) {
        memlimit = crypto_pwhash_MEMLIMIT_MIN;
    }

    MUST_SUCCEED(Sodium::crypto_pwhash_str(
        result, passwd, (unsigned long long) passwd_len,
        opslimit, memlimit
    ));

    result[crypto_pwhash_STRBYTES] = (char)0;
    *length = (unsigned long)strlen(result);

    return result;
},
{ // deinit:
    initid->ptr = NULL;
}
)

/**@FUNCTION sodium_auth(message, key) RETURNS STRING */
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
    result = fixed_buffer(result, crypto_auth_BYTES, initid->ptr);
    
    MUST_SUCCEED(crypto_auth(result, message, messageLength, key));
    
    return result;
},
{
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
}
);


/**@FUNCTION sodium_auth_verify(mac, message, key) RETURNS INTEGER */
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

    return crypto_auth_verify(mac, message, messageLength, key);
}, {
    // deinit
});


/**@FUNCTION sodium_box(message, nonce, publicKey, secretKey) RETURNS STRING */
MYSQL_STRING_FUNCTION(sodium_box,
{
    // init
    REQUIRE_ARGS(4);
    REQUIRE_STRING(0, message);
    REQUIRE_STRING(1, nonce);
    REQUIRE_STRING(2, publicKey);
    REQUIRE_STRING(3, secretKey);

    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    const char *const message = args->args[0];
    size_t messageLength = args->lengths[0];
    if (message == NULL) {
        return MYSQL_NULL;
    }

    const char *const nonce = args->args[1];
    if (args->lengths[1] != crypto_box_NONCEBYTES) {
        return MYSQL_NULL;
    }

    const char *const publicKey = args->args[2];
    if (args->lengths[2] != crypto_box_PUBLICKEYBYTES) {
        return MYSQL_NULL;
    }

    const char *const secretKey = args->args[3];
    if (args->lengths[3] != crypto_box_SECRETKEYBYTES) {
        return MYSQL_NULL;
    }

    result = fixed_buffer(result, messageLength + crypto_box_MACBYTES, initid->ptr);

    MUST_SUCCEED(crypto_box_easy(result, message, messageLength, nonce, publicKey, secretKey));

    return result;
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
});


/**@FUNCTION sodium_box_keypair() RETURNS STRING */
MYSQL_STRING_FUNCTION(sodium_box_keypair,
{
    // init
    REQUIRE_ARGS(0);

    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    result = fixed_buffer(result, crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES, initid->ptr);

    MUST_SUCCEED(crypto_box_keypair(result, result + crypto_box_PUBLICKEYBYTES));

    return result;
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
});


/**@FUNCTION sodium_box_open(cipher, nonce, publicKey, secretKey) RETURNS STRING */
MYSQL_STRING_FUNCTION(sodium_box_open,
{
    // init
    REQUIRE_ARGS(4);
    REQUIRE_STRING(0, cipher);
    REQUIRE_STRING(1, nonce);
    REQUIRE_STRING(2, publicKey);
    REQUIRE_STRING(3, secretKey);

    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    const char *const cipher = args->args[0];
    size_t cipherLength = args->lengths[0];
    if (cipher == NULL) {
        return MYSQL_NULL;
    }

    const char *const nonce = args->args[1];
    if (args->lengths[1] != crypto_box_NONCEBYTES) {
        return MYSQL_NULL;
    }

    const char *const publicKey = args->args[2];
    if (args->lengths[2] != crypto_box_PUBLICKEYBYTES) {
        return MYSQL_NULL;
    }

    const char *const secretKey = args->args[3];
    if (args->lengths[3] != crypto_box_SECRETKEYBYTES) {
        return MYSQL_NULL;
    }

    result = fixed_buffer(result, cipherLength - crypto_box_MACBYTES, initid->ptr);

    if (crypto_box_open_easy(result, cipher, cipherLength, nonce, publicKey, secretKey) != SUCCESS) {
        return MYSQL_NULL;
    }

    return result;
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
});


/* sodium_box_publickey(keyPair) RETURNS BINARY STRING */
SUBSTRING_FUNCTION(sodium_box_publickey,
    keyPair, MYSQL_BINARY_STRING,
    0, crypto_box_PUBLICKEYBYTES,
    crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES
);


/**@FUNCTION sodium_box_seal(message, publicKey) RETURNS STRING */
MYSQL_STRING_FUNCTION(sodium_box_seal,
{
    // init
    REQUIRE_ARGS(2);
    REQUIRE_STRING(0, message);
    REQUIRE_STRING(1, publicKey);

    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    const char *const message = args->args[0];
    size_t messageLength = args->lengths[0];
    if (message == NULL) {
        return MYSQL_NULL;
    }

    const char *const publicKey = args->args[1];
    if (args->lengths[1] != crypto_box_PUBLICKEYBYTES) {
        return MYSQL_NULL;
    }

    result = fixed_buffer(messageLength + crypto_box_SEALBYTES);

    MUST_SUCCEED(crypto_box_seal(result, message, messageLength, publicKey));

    return result;
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
});


/**@FUNCTION sodium_box_seal_open(cipher, publicKey, secretKey) RETURNS STRING */
MYSQL_STRING_FUNCTION(sodium_box_seal_open,
{
    // init
    REQUIRE_ARGS(3);
    REQUIRE_STRING(0, cipher);
    REQUIRE_STRING(1, publicKey);
    REQUIRE_STRING(2, secretKey);

    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    const char *const cipher = args->args[0];
    size_t cipherLength = args->lengths[0];
    if (cipher == NULL) {
        return MYSQL_NULL;
    }

    const char *const publicKey = args->args[1];
    if (args->lengths[1] != crypto_box_PUBLICKEYBYTES) {
        return MYSQL_NULL;
    }

    const char *const secretKey = args->args[2];
    if (args->lengths[2] != crypto_box_SECRETKEYBYTES) {
        return MYSQL_NULL;
    }

    result = fixed_buffer(cipherLength - crypto_box_SEALBYTES);

    MUST_SUCCEED(crypto_box_seal_open(result, cipher, cipherLength, publicKey, secretKey));

    return result;
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
});


/* sodium_box_secretkey(keyPair) RETURNS STRING */

SUBSTRING_FUNCTION(sodium_box_secretkey,
    keyPair, MYSQL_BINARY_STRING,
    crypto_box_PUBLICKEYBYTES, crypto_box_SECRETKEYBYTES,
    crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES
);


/* sodium_box_seed_keypair(seed) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_box_seed_keypair,
{
    // init
    REQUIRE_ARGS(1);
    REQUIRE_STRING(0, seed);

    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    const char *const seed = args->args[0];
    if (args->lengths[0] != crypto_box_SEEDBYTES) {
        return MYSQL_NULL;
    }

    result = fixed_buffer(result, crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES, initid->ptr);

    MUST_SUCCEED(crypto_box_seed_keypair(result, result + crypto_box_PUBLICKEYBYTES, seed));

    return result;
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
});


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

    result = fixed_buffer(result, hashLength, initid->ptr);
    
    MUST_SUCCEED(crypto_generichash(hashLength, message, messageLength, key, keyLength));
    
    return result;
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
});


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
    MUST_SUCCEED(crypto_kdf_derive_from_key(result, keyLength, subkeyID, context, masterKey));
    return result;
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
});


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

    MUST_SUCCEED(crypto_kx_client_session_keys(
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
    MUST_SUCCEED(crypto_kx_keypair(result, result + crypto_kx_PUBLICKEYBYTES));
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

    MUST_SUCCEED(crypto_kx_seed_keypair(result, result + crypto_kx_PUBLICKEYBYTES, seed));

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

    MUST_SUCCEED(crypto_kx_server_session_keys(
        result, result + crypto_kx_SESSIONKEYBYTES,
        serverPublicKey, serverSecretKey, clientPublicKey
    ));

    return result;
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
});


/* sodium_pwhash(hashLength, password, salt, securityLevel) RETURNS BINARY STRING */
/* sodium_pwhash(hashLength, password, salt, operationLimit, memoryLimit) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_pwhash,
{
    // init
    REQUIRE_CONST_INTEGER(0, hashLength);
    const long long hashLength = *((long long *)args->args[0]);
    if (hashLength < crypto_pwhash_BYTES_MIN) {
        strcpy(message, "hashLength is too small");
        return 1;
    }
    if (hashLength > crypto_pwhash_BYTES_MAX) {
        strcpy(message, "hashLength is too large for Sodium");
        return 1;
    }
    if (hashLength > mysql_RESULT_LENGTH) {
        strcpy(message, "hashLength is too large for mysql-sodium v0.1");
        return 1;
        // initid->ptr would need to be used for both
        // (1) storing the securityLevel
        // (2) holding the allocated string buffer
    }
    if (hashLength > 0xffffffff) {
        // Cannot fit hashLength into length pointer
        strcpy(message, "hashLength is too large for mysql");
        return 1;
    }

    REQUIRE_STRING(1, password);
    REQUIRE_STRING(2, salt);

    switch (args->arg_count) {
        case 4: {
            REQUIRE_CONST_STRING(3, securityLevel);
            const security_level *const matching_level = pwhash_security_preset(args->args[3], args->lengths[3]);

            if (matching_level == NULL) {
                strcpy(message, pwhash_SECURITY_INVALID);
                return 1;
            } else {
                // Store security level in pointer for main function
                initid->ptr = (char *)matching_level;
            }

        } break;
        case 5: {
            REQUIRE_CONST_INTEGER(3, memoryLimit);
            REQUIRE_CONST_INTEGER(4, operationLimit);

            const long long    memlimit = *((long long *)args->args[3]);
            const long long    opslimit = *((long long *)args->args[4]);
            if (memlimit < 0 || memlimit > SIZE_MAX) {
                strcpy(message, "memoryLimit is out of bounds");
                return 1;
            }
            if (opslimit < 0) {
                strcpy(message, "operationLimit is out of bounds");
                return 1;
            }
        } break;
        default: {
            strcpy(message, "4-5 arguments required");
            return 1;
        }
    }

    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    const long long hashLength = *((long long *)args->args[0]);

    const char             *passwd = args->args[1];
    size_t                  passwdLength = args->lengths[1];

    const char             *salt = args->args[2];
    size_t                  saltLength = args->lengths[2];

    size_t                  memlimit;
    unsigned long long      opslimit;

    if (initid->ptr != NULL) {
        const security_level   *ptr = (security_level *)(initid->ptr);

        memlimit = ptr->memlimit;
        opslimit = ptr->opslimit;

    } else {
        memlimit = args->args[3] ? *((unsigned long long *)args->args[3]) : 0;
        opslimit = args->args[4] ? (size_t)*((long long *)args->args[4]) : 0;
    }


    if (passwd == NULL || passwdLength <= 0 || passwdLength >= 0xffffffff) {
        return MYSQL_NULL;
    }

    if (opslimit < crypto_pwhash_OPSLIMIT_MIN) {
        opslimit = crypto_pwhash_OPSLIMIT_MIN;
    }

    if (memlimit < crypto_pwhash_MEMLIMIT_MIN) {
        memlimit = crypto_pwhash_MEMLIMIT_MIN;
    }

    MUST_SUCCEED(Sodium::crypto_pwhash(
        result, hashLength,
        passwd, (unsigned long long) passwdLength,
        salt,
        opslimit, memlimit,
        crypto_pwhash_ALG_DEFAULT
    ));

    *length = (unsigned long)hashLength;

    return result;

}, {
    // deinit
    initid->ptr = NULL;
});


/* sodium_pwhash_str_needs_rehash(hashStr, securityLevel) RETURNS INTEGER */
/* sodium_pwhash_str_needs_rehash(hashStr, operationLimit, memoryLimit) RETURNS INTEGER */
MYSQL_INTEGER_FUNCTION(sodium_pwhash_str_needs_rehash,
{
    // init
    REQUIRE_STRING(0, hashStr);

    switch (args->arg_count) {
        case 2: {
            REQUIRE_CONST_STRING(1, securityLevel);
            const security_level *const matching_level = pwhash_security_preset(args->args[1], args->lengths[1]);

            if (matching_level == NULL) {
                strcpy(message, pwhash_SECURITY_INVALID);
                return 1;
            } else {
                // Store security level in pointer for main function
                initid->ptr = (char *)matching_level;
            }

        } break;
        case 3: {
            REQUIRE_CONST_INTEGER(1, memoryLimit);
            REQUIRE_CONST_INTEGER(2, operationLimit);

            const long long    memlimit = *((long long *)args->args[1]);
            const long long    opslimit = *((long long *)args->args[2]);
            if (memlimit < 0 || memlimit > SIZE_MAX) {
                strcpy(message, "memoryLimit is out of bounds");
                return 1;
            }
            if (opslimit < 0) {
                strcpy(message, "operationLimit is out of bounds");
                return 1;
            }
        } break;
        default: {
            strcpy(message, "2-3 arguments required");
            return 1;
        }
    }
}, {
    // main
    const char             *hashStr = args->args[0];
    size_t                  hashStrLength = args->lengths[0];

    if (hashStr == NULL || hashStrLength != crypto_pwhash_STRBYTES) {
        return MYSQL_NULL;
    }

    size_t                  memlimit;
    unsigned long long      opslimit;

    if (initid->ptr != NULL) {
        const security_level   *ptr = (security_level *)(initid->ptr);

        memlimit = ptr->memlimit;
        opslimit = ptr->opslimit;

    } else {
        memlimit = args->args[1] ? *((unsigned long long *)args->args[1]) : 0;
        opslimit = args->args[2] ? (size_t)*((long long *)args->args[2]) : 0;
    }


    if (opslimit < crypto_pwhash_OPSLIMIT_MIN) {
        opslimit = crypto_pwhash_OPSLIMIT_MIN;
    }

    if (memlimit < crypto_pwhash_MEMLIMIT_MIN) {
        memlimit = crypto_pwhash_MEMLIMIT_MIN;
    }

    return Sodium::crypto_pwhash_str_needs_rehash(hashStr, opslimit, memlimit);
}, {
    // deinit
    initid->ptr = NULL;
});


/* sodium_pwhash_str_verify(hashStr, password) RETURNS INTEGER */
MYSQL_INTEGER_FUNCTION(sodium_pwhash_str_verify,
{
    // init
    REQUIRE_ARGS(2);
    REQUIRE_STRING(0, hashStr);
    REQUIRE_STRING(1, password);
}, {
    // main
    const char             *hashStr = args->args[0];
    size_t                  hashStrLength = args->lengths[0];

    if (hashStrLength == 0 || hashStrLength > crypto_pwhash_STRBYTES) {
        return FAIL;
    }

    // crypto_pwhash_str_verify needs a zero-terminated string, which mysql does not provide
    const char              hashStrCopy[crypto_pwhash_STRBYTES + 1];
    strcpy(hashStrCopy, hashStr, hashStrLength);
    hashStrCopy[hashStrLength] = 0;


    const char             *passwd = args->args[1];
    size_t                  passwdLength = args->lengths[1];

    const int verifySuccess = crypto_pwhash_str_verify(hashStrCopy, passwd, passwdLength);

    sodium_memzero(hashStrCopy, sizeof(hashStrCopy));

    return verifySuccess;
}, {
    // deinit
});


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
        return MYSQL_NULL;
    }

    result = fixed_buffer(result, messageLength + crypto_secretbox_MACBYTES, initid->ptr);

    MUST_SUCCEED(crypto_secretbox_easy(result, message, messageLength, nonce, key));

    return result;
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
});


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
        return MYSQL_NULL;
    }

    result = fixed_buffer(result, cipher + crypto_secretbox_MACBYTES, initid->ptr);

    MUST_SUCCEED(crypto_secretbox_open_easy(result, cipher, cipherLength, nonce, key));

    return result;
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
});


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
        return MYSQL_NULL;
    }

    result = fixed_buffer(result, messageLength + crypto_sign_BYTES, initid->ptr);

    MUST_SUCCEED(crypto_sign(result, NULL, message, messageLength, secretKey));

    return result;
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
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
        return MYSQL_NULL;
    }

    result = fixed_buffer(result, crypto_sign_BYTES, initid->ptr);

    MUST_SUCCEED(crypto_sign_detached(result, NULL, message, messageLength, secretKey));

    return result;
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
});


/* sodium_sign_keypair() RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_sign_keypair,
{
    // init
    REQUIRE_ARGS(0);
    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    result = fixed_buffer(result, crypto_sign_PUBLICKEYBYTES + crypto_sign_SECRETKEYBYTES, initid->ptr);
    MUST_SUCCEED(crypto_sign_keypair(result, result + crypto_sign_PUBLICKEYBYTES));
    return result;
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
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

    if (signedMessage == NULL || publicKey != crypto_sign_PUBLICKEYBYTES) {
        return MYSQL_NULL;
    }

    result = dynamic_buffer(result, signedMessageLength, initid->ptr);
    
    unsigned long long messageLength;

    if (crypto_sign(result, &messageLength, signedMessage, signedMessageLength, publicKey) != SUCCESS) {
        return MYSQL_NULL;
    }

    *length = (unsigned long)messageLength;

    return result;
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
});


/* sodium_sign_publickey_from_secretkey(secretKey) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_sign_publickey_from_secretkey,
{
    // init
    REQUIRE_ARGS(1);
    REQUIRE_STRING(0, secretKey);
    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    // TODO find the implementation for this
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
});


/* sodium_sign_publickey(keyPair) RETURNS BINARY STRING */
SUBSTRING_FUNCTION(sodium_sign_publickey, keyPair, MYSQL_BINARY_STRING, 0, crypto_sign_PUBLICKEYBYTES, crypto_sign_PUBLICKEYBYTES + crypto_sign_SECRETKEYBYTES);

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

    if (seedLength != sodium_sign_SEEDBYTES) {
        return MYSQL_NULL;
    }

    result = fixed_buffer(result, crypto_sign_PUBLICKEYBYTES + crypto_sign_SECRETKEYBYTES, initid->ptr);
    MUST_SUCCEED(crypto_sign_seed_keypair(result, result + crypto_sign_PUBLICKEYBYTES, seed));
    return result;
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
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

    return crypto_sign_verify_detached(signature, message, messageLength, publicKey);
}, {
    // deinit
});


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

    if (crypto_shorthash(result, message, messageLength, key) != SUCCESS) {
        return MYSQL_NULL;
    }

    *length = (unsigned long)messageLength;

    return result;

}, {
    // deinit
});


#define MAX_PAD_LENGTH 1024

/* _sodium_pad(input) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(_sodium_pad,
{
    // init
    REQUIRE_ARGS(2);
    args->arg_type[0] = STRING_RESULT;
    REQUIRE_INTEGER(1, blockSize);
    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    const char             *input = args->args[0];
    size_t                  inputLength = args->lengths[0];

    long long               blockSize = *(long long*)args->args[1];

    if (input == NULL
        || blockSize < 1 || blockSize > 0xffffffff
    ) {
        return MYSQL_NULL;
    }

    size_t                  maxLength = inputLength + MAX_PAD_LENGTH;

    result = dynamic_buffer(result, maxLength, initid->ptr);

    strcpy(result, input, inputLength);

    unsigned long long paddedLength;

    if (sodium_pad(&paddedLength, result, inputLength, blockSize, maxLength) != SUCCESS) {
        return MYSQL_NULL;
    }

    *length = (unsigned long)paddedLength;

    return result;
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
});


/* _sodium_unpad() RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(_sodium_unpad,
{
    // init
    REQUIRE_ARGS(2);
    args->arg_type[0] = STRING_RESULT;
    REQUIRE_INTEGER(1, blockSize);
    initid->max_length = MYSQL_BINARY_STRING;
}, {
    // main
    const char             *input = args->args[0];
    size_t                  inputLength = args->lengths[0];

    long long               blockSize = *(long long*)args->args[1];

    if (input == NULL
        || blockSize < 1 || blockSize > 0xffffffff
    ) {
        return MYSQL_NULL;
    }

    result = dynamic_buffer(result, inputLength, initid->ptr);

    strcpy(result, input, inputLength);

    unsigned long long messageLength;

    if (sodium_unpad(&messageLength, result, inputLength, blockSize) != SUCCESS) {
        return MYSQL_NULL;
    }

    *length = (unsigned long)messageLength;

    return result;
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
});


/* sodium_auth_keygen() RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_auth_keygen,
{
    // init
    REQUIRE_ARGS(0);

}, {
    // main
    // TODO wrap crypto_auth_keygen(result)
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
});


/* sodium_generichash_keygen() RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_generichash_keygen,
{
    // init
    REQUIRE_ARGS(0);

}, {
    // main
    // TODO wrap crypto_auth_keygen(result)
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
});


/* sodium_kdf_keygen() RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_kdf_keygen,
{
    // init
    REQUIRE_ARGS(0);

}, {
    // main
    // TODO wrap crypto_kdf_keygen(result)
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
});


/* sodium_secretbox_keygen() RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_secretbox_keygen,
{
    // init
    REQUIRE_ARGS(0);

}, {
    // main
    // TODO wrap crypto_secretbox_keygen(result)
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
});


/* sodium_shorthash_keygen() RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_shorthash_keygen,
{
    // init
    REQUIRE_ARGS(0);

}, {
    // main
    // TODO wrap crypto_shorthash_keygen(result)
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
});


/* __UDF__() RETURNS BINARY STRING */
/*
MYSQL_STRING_FUNCTION(__UDF__,
{
    // init
    REQUIRE_ARGS(0);

}, {
    // main
}, {
    // deinit
    if (initid->ptr != NULL)  free(initid->ptr);
});
*/