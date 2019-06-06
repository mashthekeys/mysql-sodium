#include "sodium_udf.h"

struct security_level {
    const char               *name;
    const size_t              nameLength;
    const unsigned long long  opslimit;
    const size_t              memlimit;
};

const size_t            PWHASH_TYPES = 5;

const security_level    PWHASH_TYPE_LIST[PWHASH_TYPES] = {{
    "INTERACTIVE",
    sizeof("INTERACTIVE") - 1,
    crypto_pwhash_OPSLIMIT_INTERACTIVE,
    crypto_pwhash_MEMLIMIT_INTERACTIVE
}, {
    "MAX",
    sizeof("MAX") - 1,
    crypto_pwhash_OPSLIMIT_MAX,
    crypto_pwhash_MEMLIMIT_MAX
}, {
    "MIN",
    sizeof("MIN") - 1,
    crypto_pwhash_OPSLIMIT_MIN,
    crypto_pwhash_MEMLIMIT_MIN
}, {
    "MODERATE",
    sizeof("MODERATE") - 1,
    crypto_pwhash_OPSLIMIT_MODERATE,
    crypto_pwhash_MEMLIMIT_MODERATE
}, {
    "SENSITIVE",
    sizeof("SENSITIVE") - 1,
    crypto_pwhash_OPSLIMIT_SENSITIVE,
    crypto_pwhash_MEMLIMIT_SENSITIVE
}};

const char pwhash_SECURITY_INVALID[] = "securityLevel must be INTERACTIVE, MODERATE, SENSITIVE, MAX, or MIN.";

const security_level *pwhash_security_preset(const char* securityLevel, size_t securityLevelLength) {
    const security_level *matching_level = NULL;
    long long i;

    for (i = 0; i < PWHASH_TYPES; ++i) {
        const char *type = PWHASH_TYPE_LIST[i].name;
        size_t typeLength = PWHASH_TYPE_LIST[i].nameLength;

        if (securityLevelLength == typeLength
            && strncasecmp(type, securityLevel, typeLength) == 0
        ) {
            matching_level = PWHASH_TYPE_LIST + i;
            break;
        }
    }
    return matching_level;
}

/** SODIUM_PWHASH(hashLength, password, salt, securityLevel) RETURNS VARBINARY
 *
 *  Derive a key from a password.  securityLevel must be one of the string constants
 *  'INTERACTIVE', 'MODERATE', 'SENSITIVE', 'MAX', or 'MIN'.
 *
 *  sodium_pwhash(hashLength, password, salt, operationLimit, memoryLimit) RETURNS VARBINARY
 *
 *  Derive a key from a password.  operationLimit and memoryLimit must be integers.
 *
 * @CREATE FUNCTION sodium_pwhash RETURNS STRING
 */
MYSQL_STRING_FUNCTION(sodium_pwhash,
{
    // init
    initid->maybe_null = 1;
    initid->max_length = MYSQL_BINARY_STRING;

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
        strcpy(message, "hashLength is too large for mysql-sodium");
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
}, {
    // main
    const long long hashLength = *((long long *)args->args[0]);

    const char *const       passwd = args->args[1];
    const size_t            passwdLength = args->lengths[1];

    const char *const       salt = args->args[2];
    const size_t            saltLength = args->lengths[2];

    size_t                  memlimit;
    unsigned long long      opslimit;

    if (initid->ptr != NULL) {
        const security_level *const  ptr = (security_level *)(initid->ptr);

        memlimit = ptr->memlimit;
        opslimit = ptr->opslimit;

    } else {
        memlimit = args->args[3] ? (size_t)*((unsigned long long *)args->args[3]) : 0;
        opslimit = args->args[4] ? *((unsigned long long *)args->args[4]) : 0;
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


/** SODIUM_PW_MEMORY(securityLevel) RETURNS INTEGER
 *
 *  Get the value of the memory limit parameter for a given SODIUM_PW security level,
 *  which must be 'INTERACTIVE', 'MODERATE', 'SENSITIVE', 'MAX', or 'MIN'.
 *
 * @CREATE FUNCTION sodium_pw_memory RETURNS INTEGER */
MYSQL_INTEGER_FUNCTION(sodium_pw_memory,
{
    // init
    initid->maybe_null = 1;

    REQUIRE_CONST_STRING(0, securityLevel);

    initid->ptr = (char*)pwhash_security_preset(args->args[0], args->lengths[0]);
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


/** SODIUM_PW_OPERATIONS(securityLevel) RETURNS INTEGER
 *
 *  Get the value of the operation limit parameter for a given SODIUM_PW security level,
 *  which must be 'INTERACTIVE', 'MODERATE', 'SENSITIVE', 'MAX', or 'MIN'.
 *
 * @CREATE FUNCTION sodium_pw_operations RETURNS INTEGER */
MYSQL_INTEGER_FUNCTION(sodium_pw_operations,
{
    // init
    initid->maybe_null = 1;

    REQUIRE_CONST_STRING(0, securityLevel);

    initid->ptr = (char*)pwhash_security_preset(args->args[0], args->lengths[0]);
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

/** SODIUM_PW(hashLength, password, salt, securityLevel)
 *  RETURNS VARCHAR(crypto_pwhash_STRBYTES) CHARACTER SET ascii COLLATE ascii_bin
 *
 *  Derive a self-contained salted ASCII hash from a password.
 *  securityLevel must be one of the string constants
 *  'INTERACTIVE', 'MODERATE', 'SENSITIVE', 'MAX', or 'MIN'.
 *
 *  SODIUM_PW(hashLength, password, salt, operationLimit, memoryLimit)
 *  RETURNS VARCHAR(crypto_pwhash_STRBYTES) CHARACTER SET ascii COLLATE ascii_bin
 *
 *  Derive a self-contained salted ASCII hash from a password.
 *  operationLimit and memoryLimit must be integers.
 *
 * @CREATE FUNCTION sodium_pw RETURNS STRING
 * @ALIAS FUNCTION sodium_pwhash_str RETURNS STRING
 */
MYSQL_STRING_FUNCTION(sodium_pw,
{ // init:
    initid->maybe_null = 1;
    initid->max_length = crypto_pwhash_STRBYTES;

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

    return 0;
},
{ // main:
    const char *const       passwd = args->args[0];
    const size_t            passwdLength = args->lengths[0];
    size_t                  memlimit;
    unsigned long long      opslimit;

    if (initid->ptr != NULL) {
        const security_level *const ptr = (security_level *)(initid->ptr);

        memlimit = ptr->memlimit;
        opslimit = ptr->opslimit;

    } else {
        memlimit = args->args[1] ? (size_t)*((unsigned long long *)args->args[1]) : 0;
        opslimit = args->args[2] ? *((unsigned long long *)args->args[2]) : 0;
    }


    if (passwd == NULL || passwdLength < crypto_pwhash_PASSWD_MIN || passwdLength > crypto_pwhash_PASSWD_MAX) {
        return_MYSQL_NULL(NULL);
    }

    if (opslimit < crypto_pwhash_OPSLIMIT_MIN) {
        opslimit = crypto_pwhash_OPSLIMIT_MIN;
    }

    if (memlimit < crypto_pwhash_MEMLIMIT_MIN) {
        memlimit = crypto_pwhash_MEMLIMIT_MIN;
    }

    MUST_SUCCEED(Sodium::crypto_pwhash_str(
        result, passwd, (unsigned long long) passwdLength,
        opslimit, memlimit
    ));

    // Null-terminate the buffer then read the length in case crypto_pwhash_str returned a shorter string */
    result[crypto_pwhash_STRBYTES] = (char)0;
    *length = (unsigned long)strlen(result);

    return result;
},
{ // deinit:
    initid->ptr = NULL;
});

UDF_STRING_ALIAS(sodium_pwhash_str, sodium_pw);


/** SODIUM_PW_OUTDATED(hashStr, securityLevel) RETURNS INTEGER
 *
 *  Determine whether a stored salted hash meets security parameters.
 *  securityLevel must be 'INTERACTIVE', 'MODERATE', 'SENSITIVE', 'MAX', or 'MIN'
 *
 *  SODIUM_PW_OUTDATED(hashStr, operationLimit, memoryLimit) RETURNS INTEGER
 *
 *  Determine whether a stored salted hash meets security parameters.
 *  operationLimit and memoryLimit must be integers.
 *
 *  Returns 0 for valid hashes which meet the security parameterrs.
 *  Returns 1 for valid hashes which DO NOT meet the security parameterrs.
 *  Returns -1 for invalid hashes and other errors.
 *
 * @CREATE FUNCTION sodium_pw_outdated RETURNS INTEGER
 * @ALIAS FUNCTION sodium_pwhash_str_needs_rehash RETURNS INTEGER
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
    const char *const       hashStr = args->args[0];
    const size_t            hashStrLength = args->lengths[0];

    if (hashStr == NULL || hashStrLength != crypto_pwhash_STRBYTES) {
        return FAIL;
    }

    size_t                  memlimit;
    unsigned long long      opslimit;

    if (initid->ptr != NULL) {
        const security_level   *ptr = (security_level *)(initid->ptr);

        memlimit = ptr->memlimit;
        opslimit = ptr->opslimit;

    } else {
        memlimit = args->args[1] ? (size_t)*((unsigned long long *)args->args[1]) : 0;
        opslimit = args->args[2] ? *((unsigned long long *)args->args[2]) : 0;
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


/** SODIUM_PW_VERIFY(hashStr, password) RETURNS INTEGER
 *
 *  Verifies that a password matches a hash.
 *
 *  Returns 0 if the match is successful, or non-zero on error.
 *
 * @CREATE FUNCTION sodium_pw_verify RETURNS INTEGER
 * @ALIAS FUNCTION sodium_pwhash_str_verify RETURNS INTEGER
 */
MYSQL_INTEGER_FUNCTION(sodium_pw_verify,
{
    // init
    REQUIRE_ARGS(2);
    REQUIRE_STRING(0, hashStr);
    REQUIRE_STRING(1, password);
}, {
    // main
    const char *const   hashStr = args->args[0];
    const size_t        hashStrLength = args->lengths[0];

    if (hashStrLength == 0 || hashStrLength > crypto_pwhash_STRBYTES) {
        return FAIL;
    }

    const char *const   passwd = args->args[1];
    const size_t        passwdLength = args->lengths[1];

    if (passwd == NULL || passwdLength < crypto_pwhash_PASSWD_MIN || passwdLength > crypto_pwhash_PASSWD_MAX) {
        return FAIL;
    }

    // crypto_pwhash_str_verify needs a zero-terminated string, which Mysql does not guarantee
    char                hashStrCopy[crypto_pwhash_STRBYTES + 1];
    memcpy(hashStrCopy, hashStr, hashStrLength);
    hashStrCopy[hashStrLength] = 0;

    const int verifySuccess = Sodium::crypto_pwhash_str_verify(hashStrCopy, passwd, passwdLength);

    Sodium::sodium_memzero(hashStrCopy, sizeof(hashStrCopy));

    return verifySuccess;
}, {
    // deinit
});

UDF_INTEGER_ALIAS(sodium_pwhash_str_verify, sodium_pw_verify);
