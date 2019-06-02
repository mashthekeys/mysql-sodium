#include "sodium_udf.h"

#if crypto_generichash_BYTES_MAX > mysql_RESULT_LENGTH
    #error "group_generichash: crypto_generichash cannot be stored in *result"
#endif

struct GenericHashProps {
    unsigned char                       isReady;
    size_t                              hashLength;
};

struct CRYPTO_ALIGN(64) GenericHashWorkArea {
    Sodium::crypto_generichash_state    state;
    GenericHashProps                    props;
};


GenericHashWorkArea *newWorkArea(size_t length)
{
    GenericHashWorkArea* workArea = (GenericHashWorkArea*) Sodium::sodium_malloc(sizeof(GenericHashWorkArea));
    workArea->props.hashLength = length;
    return workArea;
}

// Zeros the entire work area, retaining the hashLength
void zeroWorkArea(GenericHashWorkArea *workArea) {
    size_t  hashLength = workArea->props.hashLength;
    Sodium::sodium_memzero(workArea, sizeof(GenericHashWorkArea));
    workArea->props.hashLength = hashLength;
}


#define WORK_AREA_PTR   ((GenericHashWorkArea*)(initid->ptr))

#define NEW_STATE       ((crypto_generichash_state*)Sodium::sodium_malloc(Sodium::crypto_generichash_statebytes()))

#define STATE_PTR       ((crypto_generichash_state*)(initid->ptr))

bool group_generichash_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
    switch (args->arg_count) {
        case 3: {
            // group_generichash(hashLength?, message, key)
            //      Unlike the non-aggregate version, key MUST NOT be empty or NULL.
            REQUIRE_STRING(2, key);
        }
        // fall through to check args 0 and 1
        case 2: {
            // group_generichash(hashLength?, message)
            if (args->args[0] != NULL) REQUIRE_CONST_INTEGER(0, hashLength);
            if (args->args[1] != NULL) REQUIRE_STRING(1, message);
        }
        break;
        default: {
            strcpy(message, "2 or 3 arguments required");
            return 1;
        }
    }

    size_t   hashLength = args->args[0] == NULL ? (size_t)crypto_generichash_BYTES : (size_t)(long long*)args->args[0];

    if ((hashLength < crypto_generichash_BYTES_MIN) && (hashLength > crypto_generichash_BYTES_MAX)) {
        // If hashLength is provided but invalid, output for the whole function is NULL
        hashLength = 0;
    }

    initid->max_length = MYSQL_BINARY_STRING;

    initid->ptr = (char*)newWorkArea(hashLength);
}

void group_generichash_clear(UDF_INIT *initid, char *is_null, char *error) {
    GenericHashWorkArea* workArea = WORK_AREA_PTR;

    if (workArea->props.hashLength == 0) {
        *error = 1;

    } else {
        workArea->props.isReady = 0;
    }
}

void group_generichash_add(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error) {
    GenericHashWorkArea* workArea = WORK_AREA_PTR;

    const char     *message       = args->args[1];
    size_t          messageLength = args->lengths[1];

    if (workArea->props.hashLength) {
        if (workArea->props.isReady == 0) {
            if (args->arg_count > 2) {
                // group_generichash(hashLength?, message, key)
                // key is read at the start of each window, allowing each hash to have a different key
                const char     *key;
                size_t          keyLength;

                key = args->args[2];
                keyLength = args->lengths[2];

                if ((keyLength < crypto_generichash_KEYBYTES_MIN)
                    || (keyLength > crypto_generichash_KEYBYTES_MAX)
                    || (Sodium::crypto_generichash_init(
                            &(workArea->state),
                            (unsigned char*)key, keyLength,
                            workArea->props.hashLength
                       ) != SUCCESS)
                ) {
                    // If key is provided but invalid, keyLength is set to 0 and output for this group is NULL
                    zeroWorkArea(workArea);
                    *is_null = 1;
                }
            } else if (Sodium::crypto_generichash_init(&(workArea->state), NULL, 0, workArea->props.hashLength) != SUCCESS) {
                // group_generichash(hashLength?, message)
                zeroWorkArea(workArea);
                *is_null = 1;
            }
            workArea->props.isReady = 1;
        }
        if (!(*is_null)) {
            if (message == NULL) {
                // If message is NULL for any row, output is NULL for this group
                *is_null = 1;
            } else if (Sodium::crypto_generichash_update(&(workArea->state), (unsigned char*)message, messageLength) != SUCCESS) {
                // If crypto_generichash_update fails for any row, output is NULL for this group
                *is_null = 1;
            }
        }
    }
}
/**
 * FUNCTION group_generichash(hashLength?, message, key?)
 */
char *group_generichash(UDF_INIT *initid, UDF_ARGS *args,
          char *result, unsigned long *length,
          char *is_null, char *error
) {
    GenericHashWorkArea* workArea = WORK_AREA_PTR;

    if (workArea->props.hashLength == 0) {
        *error = 1;

        return NULL;
    }

    if (*is_null) {
        return NULL;
    }

    if (Sodium::crypto_generichash_final(&(workArea->state), (unsigned char*)result, workArea->props.hashLength)
        != SUCCESS
    ) {
        // If crypto_generichash_final fails, output is NULL for this group
        *is_null = 1;
        return NULL;
    }

    *length = (unsigned long)workArea->props.hashLength;

    return result;
}

void group_generichash_deinit(UDF_INIT *initid) {
    if (initid->ptr != NULL) Sodium::sodium_free(initid->ptr);
}