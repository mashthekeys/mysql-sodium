#ifndef __sodium_udf
#define __sodium_udf

#include "mysql.h"
#include "mysql/udf_registration_types.h"

namespace Sodium {
  #include <sodium.h>
}

// Used in the macro fixed_buffer
char *dynamic_buffer(char *preallocated, size_t required, void **store) {


#define fixed_buffer(preallocated, fixedLength) \
    dynamic_buffer(preallocated, fixedLength, &(initid->ptr)); \
    *length = fixedLength;



#define mysql_RESULT_LENGTH 255


#define MYSQL_STRING_FUNCTION(UDFName, initFunctionBody, mainFunctionBody, deinitFunctionBody) \
extern "C" char *UDFName(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)\
mainFunctionBody \
extern "C" bool UDFName##_init(UDF_INIT *initid, UDF_ARGS *args, char *message)\
{ { if (Sodium::sodium_init() < 0) return (strcpy(message, "Sodium initialization error"), 1); } initFunctionBody; return 0; } \
extern "C" void UDFName##_deinit(UDF_INIT *initid)\
deinitFunctionBody ;

#define MYSQL_INTEGER_FUNCTION(UDFName, initFunctionBody, mainFunctionBody, deinitFunctionBody) \
extern "C" long long UDFName(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)\
mainFunctionBody \
extern "C" bool UDFName##_init(UDF_INIT *initid, UDF_ARGS *args, char *message)\
{ { if (Sodium::sodium_init() < 0) return (strcpy(message, "Sodium initialization error"), 1); } initFunctionBody; return 0; } \
extern "C" void UDFName##_deinit(UDF_INIT *initid)\
deinitFunctionBody ;

#define MYSQL_REAL_FUNCTION(UDFName, initFunctionBody, mainFunctionBody, deinitFunctionBody) \
extern "C" double UDFName(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)\
mainFunctionBody \
extern "C" bool UDFName##_init(UDF_INIT *initid, UDF_ARGS *args, char *message)\
{ { if (Sodium::sodium_init() < 0) return (strcpy(message, "Sodium initialization error"), 1); } initFunctionBody; return 0; } \
extern "C" void UDFName##_deinit(UDF_INIT *initid)\
deinitFunctionBody ;


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
}, { \
    // main \
    const char *const substr_field = args->args[0]; \
    if (substr_field == NULL || args->lengths[0] != (total_field_length)) { \
        return MYSQL_NULL; \
    } \
//    result = fixed_buffer(result, (substr_length), initid->ptr); \
//    strcpy(result, substr_field + (substr_offset), (substr_length)); \
//    return result; \
    *length = (size_t)(substr_length); \
    return substr_field + (substr_offset); \
}, { \
    // deinit \
    if (initid->ptr != NULL)  free(initid->ptr); \
})

#define BUFFER_GENERATOR_FUNCTION(buffer_udf, generator_function, buffer_length, _max_length) \
MYSQL_STRING_FUNCTION(buffer_udf, \
{ \
    // init \
    REQUIRE_ARGS(0); \
    initid->max_length = _max_length; \
}, { \
    // main \
    result = fixed_buffer(result, buffer_length, initid->ptr); \
    MUST_SUCCEED(generator_function(result)); \
    return result; \
}, { \
    // deinit \
    if (initid->ptr != NULL)  free(initid->ptr); \
});

#endif