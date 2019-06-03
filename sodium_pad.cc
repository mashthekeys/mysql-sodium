#include "sodium_udf.h"


#define MAX_PAD_LENGTH 1024


/* block_pad(input) RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(block_pad,
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
        return_MYSQL_NULL(NULL);
    }

    size_t                  maxLength = inputLength + MAX_PAD_LENGTH;

    result = dynamic_buffer(result, maxLength, &(initid->ptr));

    memcpy(result, input, inputLength);

//    unsigned long paddedLength;

    if (Sodium::sodium_pad(length, (unsigned char*)result, inputLength, blockSize, maxLength)
        != SUCCESS
    ) {
        return_MYSQL_NULL(NULL);
    }

//    *length = (unsigned long)paddedLength;

    return result;
}, {
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
});


/* block_unpad() RETURNS BINARY STRING */
MYSQL_STRING_FUNCTION(block_unpad,
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
        return_MYSQL_NULL(NULL);
    }

    result = dynamic_buffer(result, inputLength, &(initid->ptr));

    memcpy(result, input, inputLength);

//    size_t messageLength;

    if (Sodium::sodium_unpad(length, (unsigned char*)result, inputLength, blockSize) != SUCCESS) {
        return_MYSQL_NULL(NULL);
    }

//    *length = (unsigned long)messageLength;

    return result;
}, {
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
});

