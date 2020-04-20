#!/bin/bash

# Copyright (C) 2020 Timothe Litt
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cd `dirname $0` || exit 1

# This script relies on sed, sha1sum (coreutils), as well as
# xxd - whch is sometimes packaged with 'vi'.

# See also Makefile.am, mod_md_manage_data.c.in

LOGO="ACME-Logo2.png"
#ICONS="ui-icons_ffffff_256x240.png"
JS="mod_md_manage.js"
CSS="mod_md_manage.css"

export LC_ALL=C

IN="$1"
[ -n "$IN" ] || IN="mod_md_manage_data.c.in"
IN="`dirname $IN`/`basename $IN`"
export OUT="$2"
[ -n "$OUT" ] || OUT="`dirname $IN`/`basename $IN .in`"
if [ "$IN" = "$OUT" ]; then
	echo "$OUT would over-write $IN, exiting"
	exit 2
fi

# HTTP-Date
datefmt="+%a, %d %b %Y %H:%M:%S GMT"

trap "rm -f ${OUT}.tmp" EXIT INT TERM HUP QUIT

function fileid() {
    local file="$1"
    local lmtok="$2"
    local etag="$3"

    # -r is a GNU extension, date can fail; fallback  current time.
    #  Fallback format codes are POSIX, per OpenGroup.
    if ! LM="`date -u -r $file "$datefmt" 2>/dev/null`"; then
        if ! LM="`date -u "$datefmt" 2>/dev/null`"; then
            LM=
        fi
    fi
    # sha1sum should exist; if fails, won't generate ETag.
    # Windows has "fciv -sha1" - requiring comment-stripping.
    # Not clear rest of build works w/o POSIX shell. Processed
    # source should compile, so if anything, a developer concern.
    #
    # Note that an etag value is a quoted string: Etag: "value"
    if ET="`sha1sum $file 2>/dev/null`"; then
        ET="\\\\\"`sed -e's/ .*$//g' <<< "$ET"`\\\\\""
    else
        ET=
    fi
    sed -e"s/$lmtok/\"$LM\"/g;s/$etag/\"$ET\"/g;"                -i $OUT
}

# Convert binary to C structure.  Remove all but data; replace & remove marker.

function embed_bin() {
    local fname="$1"
    local token="$2"

    xxd -i $fname | sed -e'/^  0x/!d'                              >${OUT}.tmp
    sed -e"/@@${token}_DATA@@/r ${OUT}.tmp"                      -i $OUT
    sed -e"/@@${token}_DATA@@/d"                                 -i $OUT
    fileid $fname "@@${token}_LM@@" "@@${token}_ET@@"
}

rm -f $OUT
cp -p $IN $OUT || exit 1

embed_bin "$LOGO"  'LOGO'
#embed_bin "$ICONS" 'ICONS'

# Remove large block comment (license) from source, compress leading saces,
# quote \ && ", quote line, replace & remove marker.

function embed_ctext() {
    local fname="$1"
    local token="$2"

    sed -e'/^\/\* Licensed/,/^ \*\//d'                              $fname >${OUT}.tmp
    sed -e's/^  */ /g;s/\([\\"]\)/\\\1/g;s/^\(.*\)$/"\1"/'       -i ${OUT}.tmp
    sed -e"/@@${token}_DATA@@/r ${OUT}.tmp"                      -i $OUT
    sed -e"/@@${token}_DATA@@/d"                                 -i $OUT
    fileid $fname "@@${token}_LM@@" "@@${token}_ET@@"
}

embed_ctext "$CSS" 'CSS'
embed_ctext "$JS"  'JS'

