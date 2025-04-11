#include "../../util/fd_util.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  (void)argc; (void)argv;
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  (void)data; (void)size;
  return 0 /* Input succeeded.  Keep it, if it found new coverage. */;
}
