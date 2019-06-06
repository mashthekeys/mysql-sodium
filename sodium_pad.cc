#include "sodium_udf.h"


#define MAX_PAD_LENGTH 1024


/** BLOCK_PAD(input, blockSize) RETURNS VARBINARY
 *
 *  Pads input string to a multiple of blockSize bytes.
 *
 * @CREATE FUNCTION block_pad() RETURNS STRING
 */
MYSQL_STRING_FUNCTION(block_pad,
{
    // init
    initid->maybe_null = 1;
    initid->max_length = MYSQL_BINARY_STRING;

    REQUIRE_ARGS(2);
    args->arg_type[0] = STRING_RESULT;
    REQUIRE_INTEGER(1, blockSize);
}, {
    // main
    const char *    input = args->args[0];
    const size_t    inputLength = args->lengths[0];

    const long long blockSize = *(long long*)args->args[1];

    if (input == NULL
        || blockSize < 1 || blockSize > 0xffffffff
    ) {
        return_MYSQL_NULL(NULL);
    }

    const size_t    maxLength = inputLength + MAX_PAD_LENGTH;

    result = dynamic_buffer(result, maxLength, &(initid->ptr));

    memcpy(result, input, inputLength);

    size_t paddedLength;

    if (Sodium::sodium_pad(
            &paddedLength,
            (unsigned char*)result, inputLength,
            (size_t)blockSize, maxLength
        ) != SUCCESS
    ) {
        return_MYSQL_NULL(NULL);
    }

    *length = (unsigned long)paddedLength;

    return result;
}, {
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
});


/** BLOCK_UNPAD(input, blockSize) RETURNS VARBINARY
 *
 *  Unpads input prewviously padded to a multiple of blockSize bytes.
 *
 * @CREATE FUNCTION block_unpad() RETURNS STRING
 */
MYSQL_STRING_FUNCTION(block_unpad,
{
    // init
    initid->maybe_null = 1;
    initid->max_length = MYSQL_BINARY_STRING;

    REQUIRE_ARGS(2);
    args->arg_type[0] = STRING_RESULT;
    REQUIRE_INTEGER(1, blockSize);
}, {
    // main
    const char *    input = args->args[0];
    const size_t    inputLength = args->lengths[0];

    const long long blockSize = *(long long*)args->args[1];

    if (input == NULL
        || blockSize < 1 || blockSize > 0xffffffff
    ) {
        return_MYSQL_NULL(NULL);
    }

    result = dynamic_buffer(result, inputLength, &(initid->ptr));

    memcpy(result, input, inputLength);

    size_t resultLength;

    if (Sodium::sodium_unpad(
            &resultLength,
            (unsigned char*)result, inputLength,
            blockSize
        ) != SUCCESS
    ) {
        return_MYSQL_NULL(NULL);
    }

    *length = (unsigned long)resultLength;

    return result;
}, {
    // deinit
    if (initid->ptr != NULL) free_buffer(initid->ptr);
});

