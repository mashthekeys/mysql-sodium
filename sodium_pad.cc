#include "sodium_udf.h"


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

    result = dynamic_buffer(result, maxLength, &(initid->ptr));

    strcpy(result, input, inputLength);

    unsigned long long paddedLength;

    if (Sodium::sodium_pad(&paddedLength, result, inputLength, blockSize, maxLength) != SUCCESS) {
        return MYSQL_NULL;
    }

    *length = (unsigned long)paddedLength;

    return result;
}, {
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
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

    result = dynamic_buffer(result, inputLength, &(initid->ptr));

    strcpy(result, input, inputLength);

    unsigned long long messageLength;

    if (Sodium::sodium_unpad(&messageLength, result, inputLength, blockSize) != SUCCESS) {
        return MYSQL_NULL;
    }

    *length = (unsigned long)messageLength;

    return result;
}, {
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
});

