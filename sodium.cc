/* Copyright (c) 2019 Andy Holland <github@ahweb.co.uk> Licence GPL */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <new>
#include <string>

#include "mysql.h"                      
#include "mysql/udf_registration_types.h"

namespace Sodium {
  #include <sodium.h>
}

#define mysql_RESULT_LENGTH 255

#if crypto_pwhash_STRBYTES >= mysql_RESULT_LENGTH
	#error "crypto_pwhash_STRBYTES is too large: sodium_pwhash_str_init needs to be rewritten to use malloc"
#endif


struct security_level {
	const char    	   *name;
	unsigned long long  opslimit;
	size_t              memlimit;
};

const size_t   HASH_TYPES = 5;

security_level    HASH_TYPE_LIST[HASH_TYPES] = {
	{"INTERACTIVE",	crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE},
	{"MAX",		crypto_pwhash_OPSLIMIT_MAX, crypto_pwhash_MEMLIMIT_MAX},
	{"MIN",		crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN},
	{"MODERATE",	crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE},
	{"SENSITIVE",	crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE}
};



extern "C" bool sodium_pwhash_str_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
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
        security_level *matching_level = NULL;
  	
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
}


//extern "C" void sodium_pwhash_str_deinit(UDF_INIT *initid);

extern "C" char *sodium_pwhash_str(UDF_INIT *initid, UDF_ARGS *args, char *result,
                          unsigned long *length, unsigned char *is_null,
                          char *error)
{
    const char      *passwd = args->args[0];
    size_t           passwd_len = args->lengths[0];
    long long        memlimit;
    long long        opslimit;
    security_level  *ptr;

    if (initid->ptr != NULL) {
        ptr = (security_level *)(initid->ptr);

        memlimit = (long long)crypto_pwhash_MEMLIMIT_SENSITIVE;//ptr->memlimit;
        opslimit = (long long)crypto_pwhash_OPSLIMIT_SENSITIVE;//ptr->opslimit;
//        memlimit = (long long)ptr->memlimit;
//        opslimit = (long long)ptr->opslimit;
        
    } else {
        memlimit = args->args[1] ? *((long long *)args->args[1]) : 0;
        opslimit = args->args[2] ? *((long long *)args->args[2]) : 0;
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
    
    if (Sodium::crypto_pwhash_str
        (result, passwd, (unsigned long long) passwd_len,
         (unsigned long long) opslimit, (size_t) memlimit) != 0) {
        *error = 1; // Sodium internal error
        return NULL;
    }
    
    result[crypto_pwhash_STRBYTES] = (char)0;
    *length = (unsigned long)strlen(result);
	
    return result;
}

