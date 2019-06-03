#include "sodium_udf.h"

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

const security_level *pwhash_security_preset(const char* securityLevel, size_t securityLevelLength) {
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

/* sodium_pwhash(hashLength, password, salt, securityLevel) RETURNS BINARY STRING
   sodium_pwhash(hashLength, password, salt, operationLimit, memoryLimit) RETURNS BINARY STRING */
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
        return_MYSQL_NULL(NULL);
    }

    if (opslimit < crypto_pwhash_OPSLIMIT_MIN) {
        opslimit = crypto_pwhash_OPSLIMIT_MIN;
    }

    if (memlimit < crypto_pwhash_MEMLIMIT_MIN) {
        memlimit = crypto_pwhash_MEMLIMIT_MIN;
    }

    MUST_SUCCEED(Sodium::crypto_pwhash(
        (unsigned char*) result, hashLength,
        passwd, (unsigned long long) passwdLength,
        (unsigned char*) salt,
        opslimit, memlimit,
        crypto_pwhash_ALG_DEFAULT
    ));

    *length = (unsigned long)hashLength;

    return result;

}, {
    // deinit
    initid->ptr = NULL;
});


/* sodium_pw_memory(securityLevel) RETURNS INTEGER */
MYSQL_INTEGER_FUNCTION(sodium_pw_memory,
{
    // init
    REQUIRE_CONST_STRING(0, securityLevel);

    initid->ptr = (char*)pwhash_security_preset(args->args[0], args->lengths[0]);

    initid->maybe_null = 1;

}, {
    // main
    const security_level* ptr = (const security_level*)(initid->ptr);

    if (ptr == NULL) {
        return_MYSQL_NULL(0);
    }
    return ptr->memlimit;
}, {
    // deinit
    initid->ptr = NULL;
}
);


/* sodium_pw_operations(securityLevel) RETURNS INTEGER */
MYSQL_INTEGER_FUNCTION(sodium_pw_operations,
{
    // init
    REQUIRE_CONST_STRING(0, securityLevel);

    initid->ptr = (char*)pwhash_security_preset(args->args[0], args->lengths[0]);

    initid->maybe_null = 1;

}, {
    // main
    const security_level* ptr = (const security_level*)(initid->ptr);

    if (ptr == NULL) {
        return_MYSQL_NULL(0);
    }
    return ptr->opslimit;
}, {
    // deinit
    initid->ptr = NULL;
}
);


#if crypto_pwhash_STRBYTES >= mysql_RESULT_LENGTH
    #error "crypto_pwhash_STRBYTES is too large"
#endif

/** sodium_pw(message, memoryLimit, operationLimit) RETURNS BINARY STRING
 *
 *  sodium_pw(message, securityLevel) RETURNS BINARY STRING
 *      securityLevel must be 'INTERACTIVE', 'MODERATE', 'SENSITIVE', 'MAX', or 'MIN'
 *
 * ALIAS sodium_pwhash_str
 *
 * @CREATE FUNCTION sodium_pw() RETURNS STRING
 */
MYSQL_STRING_FUNCTION(sodium_pw,
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
        return_MYSQL_NULL(NULL);
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
});

UDF_STRING_ALIAS(sodium_pwhash_str, sodium_pw);


/** sodium_pw_outdated(hashStr, securityLevel) RETURNS INTEGER
 * sodium_pw_outdated(hashStr, operationLimit, memoryLimit) RETURNS INTEGER
 * ALIAS sodium_pwhash_str_needs_rehash
 */
MYSQL_INTEGER_FUNCTION(sodium_pw_outdated,
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
        return_MYSQL_NULL(FAIL);
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

UDF_INTEGER_ALIAS(sodium_pwhash_str_needs_rehash, sodium_pw_outdated);


/** sodium_pw_verify(hashStr, password) RETURNS INTEGER
 *  ALIAS sodium_pwhash_str_verify
 */
MYSQL_INTEGER_FUNCTION(sodium_pw_verify,
{
    // init
    REQUIRE_ARGS(2);
    REQUIRE_STRING(0, hashStr);
    REQUIRE_STRING(1, password);
}, {
    // main
    const char     *hashStr = args->args[0];
    size_t          hashStrLength = args->lengths[0];

    if (hashStrLength == 0 || hashStrLength > crypto_pwhash_STRBYTES) {
        return FAIL;
    }

    // crypto_pwhash_str_verify needs a zero-terminated string, which Mysql does not provide
    char            hashStrCopy[crypto_pwhash_STRBYTES + 1];
    memcpy(hashStrCopy, hashStr, hashStrLength);
    hashStrCopy[hashStrLength] = 0;


    char           *passwd = args->args[1];
    size_t          passwdLength = args->lengths[1];

    const int verifySuccess = Sodium::crypto_pwhash_str_verify(hashStrCopy, passwd, passwdLength);

    Sodium::sodium_memzero(hashStrCopy, sizeof(hashStrCopy));

    return verifySuccess;
}, {
    // deinit
});

UDF_INTEGER_ALIAS(sodium_pwhash_str_verify, sodium_pw_verify);
