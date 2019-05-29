#include "mysql.h"
#include "mysql/udf_registration_types.h"

#define MYSQL_RETURN_AS_BLOB (65*1024)

#define MYSQL_STRING_FUNCTION(UDFName, initFunctionBody, mainFunctionBody, deinitFunctionBody) \
extern "C" bool UDFName##_init(UDF_INIT *initid, UDF_ARGS *args, char *message)\
initFunctionBody \
extern "C" char *UDFName(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)\
mainFunctionBody \
extern "C" void UDFName##_deinit(UDF_INIT *initid)\
deinitFunctionBody ;

#define MYSQL_INTEGER_FUNCTION(UDFName, initFunctionBody, mainFunctionBody, deinitFunctionBody) \
extern "C" bool UDFName##_init(UDF_INIT *initid, UDF_ARGS *args, char *message)\
initFunctionBody \
extern "C" long long UDFName(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)\
mainFunctionBody \
extern "C" void UDFName##_deinit(UDF_INIT *initid)\
deinitFunctionBody ;

#define MYSQL_REAL_FUNCTION(UDFName, initFunctionBody, mainFunctionBody, deinitFunctionBody) \
extern "C" bool UDFName##_init(UDF_INIT *initid, UDF_ARGS *args, char *message)\
initFunctionBody \
extern "C" double UDFName(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)\
mainFunctionBody \
extern "C" void UDFName##_deinit(UDF_INIT *initid)\
deinitFunctionBody ;

