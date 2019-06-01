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
char *dynamic_buffer(char *preallocated, size_t required, void **store) {
    if (required < mysql_RESULT_LENGTH)  {
        return preallocated;
    }

    char* buffer = Sodium::sodium_malloc(required + 1);

    if (store != NULL) *store = buffer;

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

