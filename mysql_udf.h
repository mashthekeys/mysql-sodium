#include "mysql.h"
#include "mysql/udf_registration_types.h"

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

