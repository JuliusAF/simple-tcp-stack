#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi
set -ex
prog="$1"
shift
gdb \
  -ex "set solib-search-path /usr/local/lib" \
  -ex "set env ld_library_path=../src" \
  -ex "set follow-fork-mode parent" \
  -ex "set exec-wrapper env 'LD_PRELOAD=/usr/local/lib/libanpnetstack.so'" \
  --args "$prog" "$@"