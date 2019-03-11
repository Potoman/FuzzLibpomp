#!/bin/bash

. $(dirname $0)/../custom-build.sh $1 $2
. $(dirname $0)/../common.sh

#get_git_revision https://github.com/Parrot-Developers/libpomp.git  a2a3bcbbfa8700b7c726827b5577ffb7d813e1dd SRC

rm -f *.o
#build_lib
build_fuzzer

for f in pomp_addr.c pomp_buffer.c pomp_conn.c pomp_ctx.c pomp_decoder.c pomp_encoder.c pomp_log.c pomp_loop.c pomp_msg.c pomp_prot.c pomp_timer.c; do
  $CC $CFLAGS -c SRC/src/$f -I SRC/include &
done
wait

if [[ $FUZZING_ENGINE == "hooks" ]]; then
  # Link ASan runtime so we can hook memcmp et al.
  LIB_FUZZING_ENGINE="-fsanitize=address"
fi
set -x
$CXX $CXXFLAGS *.o $LIB_FUZZING_ENGINE $SCRIPT_DIR/target.cc -I SRC/src -I SRC/include -o $EXECUTABLE_NAME_BASE
