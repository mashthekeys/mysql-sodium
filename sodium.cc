/* Copyright (c) 2019 Andy Holland <github@ahweb.co.uk> Licence GPL */
/* Some apects of API design are modelled after PHP's Sodium extension under BSD 2-Clause Simplified Licence */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <new>
#include <string>

#include "sodium_udf.h"

// Used in the macro fixed_buffer
char *dynamic_buffer(char *preallocated, size_t required, char *alloc_result) {
    if (required < mysql_RESULT_LENGTH)  {
        return preallocated;
    }

    const char* buffer = malloc(required + 1);

    if (alloc_result != NULL) *alloc_result = buffer;

    return buffer;
}


#include "sodium_auth.cc"
#include "sodium_box.cc"
#include "sodium_hash.cc"
#include "sodium_kdf.cc"
#include "sodium_kx.cc"
#include "sodium_pad.cc"
#include "sodium_pwhash.cc"
#include "sodium_secretbox.cc"
#include "sodium_sign.cc"

