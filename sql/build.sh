#!/bin/bash

if [ -z $1 ]; then
    SONAME='sodium.so';
else
    SONAME="$1";
fi

# Check for BSD sed which uses -E instead of -r
FLAGS=$(sed -r '' </dev/null >/dev/null 2>&1 && echo 'r' || echo 'E')

grep -o$FLAGS '@CREATE[^;*/]*' ../*.cc \
| sed -$FLAGS 's/^[-.$_0-9A-Za-z/]+:@(CREATE|ALIAS)/CREATE/' \
| sed -$FLAGS "s/\$/ SONAME '$SONAME';/" \
| sort >InstallSodium.sql

grep -o$FLAGS '@ALIAS[^;*/]*' ../*.cc \
| sed -$FLAGS 's/.+:@(CREATE|ALIAS)/CREATE/' \
| sed -$FLAGS "s/\$/ SONAME '$SONAME';/" \
| sort >InstallSodiumLongNames.sql

grep -o$FLAGS '@(CREATE|ALIAS)[^;*/]*' ../*.cc \
| sed -$FLAGS 's/^[-.$_0-9A-Za-z/]+:@(CREATE|ALIAS) +(AGGREGATE +)?FUNCTION/DROP FUNCTION IF EXISTS/' \
| sed -$FLAGS "s/ +RETURNS [A-Za-z]+[ *]*\$/;/" \
| sort >UninstallSodium.sql
