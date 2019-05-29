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

const size_t            HASH_TYPES = 5;

const security_level    HASH_TYPE_LIST[HASH_TYPES] = {
    {"INTERACTIVE", crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE},
    {"MAX",         crypto_pwhash_OPSLIMIT_MAX,         crypto_pwhash_MEMLIMIT_MAX},
    {"MIN",         crypto_pwhash_OPSLIMIT_MIN,         crypto_pwhash_MEMLIMIT_MIN},
    {"MODERATE",    crypto_pwhash_OPSLIMIT_MODERATE,    crypto_pwhash_MEMLIMIT_MODERATE},
    {"SENSITIVE",   crypto_pwhash_OPSLIMIT_SENSITIVE,   crypto_pwhash_MEMLIMIT_SENSITIVE}
};


/**@sql sodium_pwhash_str(message, securityLevel) RETURNS STRING */
/**@sql sodium_pwhash_str(message, memoryLimit, operationLimit) RETURNS STRING */
MYSQL_STRING_FUNCTION(sodium_pwhash_str,
{ // init:
    if (Sodium::sodium_init() < 0) {
        strcpy(message, "sodium_pwhash_str initialization error");
        return 1;
    }
    if (args->arg_type[0] != STRING_RESULT) {
        strcpy(message, "sodium_pwhash_str requires a string for password");
        return 1;
    }

    if (args->arg_count == 2) {
        if (args->arg_type[1] != STRING_RESULT || args->args[1] == NULL) {
            strcpy(message, "sodium_pwhash_str requires a constant string for security level");
            return 1;
        }

        long long x;
        const security_level *matching_level = NULL;

        for (x = 0; x < HASH_TYPES; ++x) {
            const char *type = HASH_TYPE_LIST[x].name;
            size_t length = strlen(type);

            if (args->lengths[1] == length
                && strncasecmp(type, args->args[1], length) == 0
            ) {
                matching_level = HASH_TYPE_LIST + x;
                break;
            }
        }

        if (matching_level == NULL) {
            strcpy(message, "sodium_pwhash_str requires one of INTERACTIVE, MODERATE, SENSITIVE, MAX, MIN for security level");
            return 1;
        } else {
            // Store security level in pointer for main function
            initid->ptr = (char *)matching_level;
        }

    } else if (args->arg_count == 3) {
        if (args->arg_type[1] != INT_RESULT || args->args[1] == NULL) {
            strcpy(message, "sodium_pwhash_str requires integer constant for memory limit");
            return 1;
        }
        if (args->arg_type[2] != INT_RESULT || args->args[2] == NULL) {
            strcpy(message, "sodium_pwhash_str requires integer constant for operation limit");
            return 1;
        }

        const long long    memlimit = *((long long *)args->args[1]);
        const long long    opslimit = *((long long *)args->args[2]);
        if (memlimit < 0 || memlimit > SIZE_MAX) {
            strcpy(message, "sodium_pwhash_str: memory limit is out of bounds");
            return 1;
        }
        if (opslimit < 0) {
            strcpy(message, "sodium_pwhash_str: operation limit is out of bounds");
            return 1;
        }

    } else {
        strcpy(message, "sodium_pwhash_str requires 2 or 3 arguments");
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
        *is_null = 1;
        return NULL;
    }

    if (opslimit < crypto_pwhash_OPSLIMIT_MIN) {
        opslimit = crypto_pwhash_OPSLIMIT_MIN;
    }

    if (memlimit < crypto_pwhash_MEMLIMIT_MIN) {
        memlimit = crypto_pwhash_MEMLIMIT_MIN;
    }

    if (Sodium::crypto_pwhash_str(
            result, passwd, (unsigned long long) passwd_len,
            opslimit, memlimit
        ) != 0
    ) {
        *error = 1; // Sodium internal error
        return NULL;
    }

    result[crypto_pwhash_STRBYTES] = (char)0;
    *length = (unsigned long)strlen(result);

    return result;
},
{ // deinit:
    initid->ptr = NULL;
}
)



/**@sql sodium_auth(VARCHAR message, VARBINARY key) RETURNS STRING */
MYSQL_INTEGER_FUNCTION(sodium_auth,
{
    // init
    if (args->arg_count != 2) {
        strcpy(message, "2 arguments required");
        return 1;
    }
    initid->max_length = MYSQL_RETURN_AS_BLOB;
},
{
    // main
},
{
    // deinit
}
);


/**@sql sodium_auth_verify(VARBINARY mac, VARCHAR message, VARBINARY key) RETURNS INTEGER */
MYSQL_INTEGER_FUNCTION(sodium_auth_verify,
{
    // init
    if (args->arg_count != 3) {
        strcpy(message, "3 arguments required");
        return 1;
    }

}, {
    // main
    return crypto_auth_verify(...);
}, {
    // deinit
});


/**@sql sodium_box(message, nonce, publicKey, secretKey) RETURNS STRING */
MYSQL_STRING_FUNCTION(sodium_box,
{
    // init
    if (args->arg_count != 4) {
        strcpy(message, "4 arguments required");
        return 1;
    }
    initid->max_length = MYSQL_RETURN_AS_BLOB;
}, {
    // main
    // TODO wrap crypto_box_easy
}, {
    // deinit
});


/**@sql sodium_box_keypair() RETURNS STRING */
MYSQL_STRING_FUNCTION(sodium_box_keypair,
{
    // init
    if (args->arg_count != 0) {
        strcpy(message, "0 arguments required");
        return 1;
    }

    initid->max_length = MYSQL_RETURN_AS_BLOB;
}, {
    // main
    // TODO wrap crypto_box_keypair(result, result + crypto_box_PUBLICKEYBYTES)
    *length = crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES;
    return result;
}, {
    // deinit
});


/**@sql sodium_box_open(message, nonce, publicKey, secretKey) RETURNS STRING */
MYSQL_STRING_FUNCTION(sodium_box_open,
{
    // init
    if (args->arg_count != 4) {
        strcpy(message, "4 arguments required");
        return 1;
    }

}, {
    // main
    // TODO wrap crypto_box_open_easy
}, {
    // deinit
});


/* sodium_box_publickey(keyPair) RETURNS STRING */
MYSQL_STRING_FUNCTION(sodium_box_publickey,
{
    // init
    if (args->arg_count != 1) {
        strcpy(message, "1 argument required");
        return 1;
    }

}, {
    // main
    // TODO strcpy(result, this->args[0], crypto_box_PUBLICKEYBYTES)
}, {
    // deinit
});


/**@sql sodium_box_seal(message, publicKey) RETURNS STRING */
MYSQL_STRING_FUNCTION(sodium_box_seal,
{
    // init
    if (args->arg_count != 0) {
        strcpy(message, "0 arguments required");
        return 1;
    }

}, {
    // main
}, {
    // deinit
});


/**@sql sodium_box_seal_open(message, publicKey, secretKey) RETURNS STRING */
MYSQL_STRING_FUNCTION(sodium_box_seal_open,
{
    // init
    if (args->arg_count != 0) {
        strcpy(message, "0 arguments required");
        return 1;
    }

}, {
    // main
}, {
    // deinit
});


/* sodium_box_secretkey(keyPair) RETURNS STRING */
MYSQL_STRING_FUNCTION(sodium_box_secretkey,
{
    // init
    if (args->arg_count != 1) {
        strcpy(message, "1 argument required");
        return 1;
    }

}, {
    // main
    // TODO strcpy(result, this->args[0] + crypto_box_PUBLICKEYBYTES, crypto_box_SECRETKEYBYTES)
}, {
    // deinit
});


/* sodium_box_seed_keypair(seed) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_box_seed_keypair,
{
    // init
    if (args->arg_count != 1) {
        strcpy(message, "1 arguments required");
        return 1;
    }

}, {
    // main
}, {
    // deinit
});


/* sodium_generichash(length, message, key?) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_generichash,
{
    // init
    if (args->arg_count == 2) {
        // sodium_generichash(length, message)

    } else if (args->arg_count == 3) {
        // sodium_generichash(length, message, key)

    } else {
        strcpy(message, "2 or 3 arguments required");
        return 1;
    }

}, {
    // main
    // TODO wrap crypto_generichash(length, message, messageLength, key, keyLength)
}, {
    // deinit
});


/* sodium_kdf_derive_from_key(length, subkeyID, context, masterKey) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_kdf_derive_from_key,
{
    // init
    if (args->arg_count != 4) {
        strcpy(message, "4 arguments required");
        return 1;
    }

}, {
    // main
    if (contextLength != crypto_kdf_CONTEXTBYTES
        || masterKeyLength != crypto_kdf_KEYBYTES
        || crypto_kdf_BYTES_MIN < length
        || crypto_kdf_BYTES_MAX > length
    ) {
        *is_null = 1;
        return NULL;
    }
    // TODO wrap crypto_kdf_derive_from_key(result, length, subkeyID, context, masterKey);
}, {
    // deinit
});


/* sodium_kx_client_session_keys(clientPublicKey, clientSecretKey, serverPublicKey) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_kx_client_session_keys,
{
    // init
    if (args->arg_count != 3) {
        strcpy(message, "3 arguments required");
        return 1;
    }

}, {
    // main
}, {
    // deinit
});


/* sodium_kx_keypair() RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_kx_keypair,
{
    // init
    if (args->arg_count != 0) {
        strcpy(message, "0 arguments required");
        return 1;
    }

}, {
    // main
    // TODO wrap crypto_kx_keypair(result, result + crypto_kx_PUBLICKEYBYTES)
    *length = crypto_kx_PUBLICKEYBYTES + crypto_kx_SECRETKEYBYTES;
}, {
    // deinit
});


/* sodium_kx_publickey() RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_kx_publickey,
{
    // init
    if (args->arg_count != 0) {
        strcpy(message, "0 arguments required");
        return 1;
    }

}, {
    // main
    // TODO implement via strcpy
}, {
    // deinit
});


/* sodium_kx_secretkey() RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_kx_secretkey,
{
    // init
    if (args->arg_count != 0) {
        strcpy(message, "0 arguments required");
        return 1;
    }

}, {
    // main
    // TODO implement via strcpy
}, {
    // deinit
});


/* sodium_kx_seed_keypair(seed) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_kx_seed_keypair,
{
    // init
    if (args->arg_count != 1) {
        strcpy(message, "1 arguments required");
        return 1;
    }

}, {
    // main
}, {
    // deinit
});


/* sodium_kx_server_session_keys(serverPublicKey, serverSecretKey, clientPublicKey) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_kx_server_session_keys,
{
    // init
    if (args->arg_count != 0) {
        strcpy(message, "____ arguments required");
        return 1;
    }

}, {
    // main
}, {
    // deinit
});


/* sodium_pwhash(hashLength, password, salt, securityLevel) RETURNS BINARY STRING */
/* sodium_pwhash(hashLength, password, salt, operationLimit, memoryLimit) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_pwhash,
{
    // init
    if (args->arg_count == 4) {

    } else if (args->arg_count == 5) {

    } else {
        strcpy(message, "4-5 arguments required");
        return 1;
    }

}, {
    // main
}, {
    // deinit
});


/* sodium_pwhash_str_needs_rehash(str, securityLevel) RETURNS INTEGER */
/* sodium_pwhash_str_needs_rehash(str, operationLimit, memoryLimit) RETURNS INTEGER */
MYSQL_INTEGER_FUNCTION(sodium_pwhash_str_needs_rehash,
{
    // init
    if (args->arg_count == 2) {

    } else if (args->arg_count == 3) {

    } else {
        strcpy(message, "2-3 arguments required");
        return 1;
    }

}, {
    // main
    // TODO wrap crypto_pwhash_str_needs_rehash
}, {
    // deinit
});


/* sodium_pwhash_str_verify(str, password) RETURNS INTEGER */
MYSQL_INTEGER_FUNCTION(sodium_pwhash_str_verify,
{
    // init
    if (args->arg_count != 2) {
        strcpy(message, "2 arguments required");
        return 1;
    }

}, {
    // main
    if (strLength != crypto_pwhash_STRBYTES) {
        *is_null = 1;
        return -1;
    }
    // TODO wrap crypto_pwhash_str_verify
}, {
    // deinit
});


/* sodium_secretbox(message, nonce, key) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_secretbox,
{
    // init
    if (args->arg_count != 3) {
        strcpy(message, "3 arguments required");
        return 1;
    }

}, {
    // main
}, {
    // deinit
});


/* sodium_secretbox_open(cipher, nonce, key) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_secretbox_open,
{
    // init
    if (args->arg_count != 3) {
        strcpy(message, "3 arguments required");
        return 1;
    }

}, {
    // main
}, {
    // deinit
});


/* sodium_sign(message, secretKey) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_sign,
{
    // init
    if (args->arg_count != 2) {
        strcpy(message, "2 arguments required");
        return 1;
    }

}, {
    // main
    *length = messageLength + crypto_sign_BYTES;

    // TODO wrap crypto_sign(result, NULL, message, messageLength, secretKey)

}, {
    // deinit
});


/* sodium_sign_detached(message, secretKey) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_sign_detached,
{
    // init
    if (args->arg_count != 2) {
        strcpy(message, "2 arguments required");
        return 1;
    }

}, {
    // main
    // TODO wrap crypto_sign_detached(result, NULL, message, messageLength, secretKey)
}, {
    // deinit
});


/* sodium_sign_keypair() RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_sign_keypair,
{
    // init
    if (args->arg_count != 0) {
        strcpy(message, "0 arguments required");
        return 1;
    }

}, {
    // main
}, {
    // deinit
});


/* sodium_sign_open(signedMessage, publicKey) RETURNS INTEGER */
MYSQL_INTEGER_FUNCTION(sodium_sign_open,
{
    // init
    if (args->arg_count != 2) {
        strcpy(message, "2 arguments required");
        return 1;
    }

}, {
    // main
}, {
    // deinit
});


/* sodium_sign_publickey_from_secretkey(secretKey) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_sign_publickey_from_secretkey,
{
    // init
    if (args->arg_count != 1) {
        strcpy(message, "1 arguments required");
        return 1;
    }

}, {
    // main
}, {
    // deinit
});


/* sodium_sign_publickey(keyPair) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_sign_publickey,
{
    // init
    if (args->arg_count != 1) {
        strcpy(message, "1 arguments required");
        return 1;
    }

}, {
    // main
}, {
    // deinit
});


/* sodium_sign_secretkey(keyPair) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_sign_secretkey,
{
    // init
    if (args->arg_count != 1) {
        strcpy(message, "1 arguments required");
        return 1;
    }

}, {
    // main
}, {
    // deinit
});


/* sodium_sign_seed_keypair(seed) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_sign_seed_keypair,
{
    // init
    if (args->arg_count != 1) {
        strcpy(message, "1 arguments required");
        return 1;
    }

}, {
    // main
    // TODO wrap crypto_sign_seed_keypair
}, {
    // deinit
});


/* sodium_sign_verify_detached(signature, message, publicKey) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_sign_verify_detached,
{
    // init
    if (args->arg_count != 3) {
        strcpy(message, "3 arguments required");
        return 1;
    }

}, {
    // main
    // TODO wrap crypto_sign_verify_detached
}, {
    // deinit
});


/* sodium_shorthash(string, key) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_shorthash,
{
    // init
    if (args->arg_count != 2) {
        strcpy(message, "2 arguments required");
        return 1;
    }

}, {
    // main
    // TODO wrap crypto_shorthash
}, {
    // deinit
});


/* _sodium_pad() RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(_sodium_pad,
{
    // init
    if (args->arg_count != 1) {
        strcpy(message, "1 arguments required");
        return 1;
    }

}, {
    // main
    // TODO wrap sodium_pad
}, {
    // deinit
});


/* _sodium_unpad() RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(_sodium_unpad,
{
    // init
    if (args->arg_count != 1) {
        strcpy(message, "1 arguments required");
        return 1;
    }

}, {
    // main
    // TODO wrap sodium_unpad
}, {
    // deinit
});


/* sodium_auth_keygen() RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_auth_keygen,
{
    // init
    if (args->arg_count != 0) {
        strcpy(message, "0 arguments required");
        return 1;
    }

}, {
    // main
    // TODO wrap crypto_auth_keygen(result)
}, {
    // deinit
});


/* sodium_generichash_keygen() RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_generichash_keygen,
{
    // init
    if (args->arg_count != 0) {
        strcpy(message, "0 arguments required");
        return 1;
    }

}, {
    // main
    // TODO wrap crypto_auth_keygen(result)
}, {
    // deinit
});


/* sodium_kdf_keygen() RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_kdf_keygen,
{
    // init
    if (args->arg_count != 0) {
        strcpy(message, "0 arguments required");
        return 1;
    }

}, {
    // main
    // TODO wrap crypto_kdf_keygen(result)
}, {
    // deinit
});


/* sodium_secretbox_keygen() RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_secretbox_keygen,
{
    // init
    if (args->arg_count != 0) {
        strcpy(message, "0 arguments required");
        return 1;
    }

}, {
    // main
    // TODO wrap crypto_secretbox_keygen(result)
}, {
    // deinit
});


/* sodium_shorthash_keygen() RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(sodium_shorthash_keygen,
{
    // init
    if (args->arg_count != 0) {
        strcpy(message, "0 arguments required");
        return 1;
    }

}, {
    // main
    // TODO wrap crypto_shorthash_keygen(result)
}, {
    // deinit
});


/* __UDF__() RETURNS BINARY STRING */
/*
MYSQL_STRING_FUNCTION(__UDF__,
{
    // init
    if (args->arg_count != 0) {
        strcpy(message, "____ arguments required");
        return 1;
    }

}, {
    // main
}, {
    // deinit
});
*/