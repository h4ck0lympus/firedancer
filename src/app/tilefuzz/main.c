#include "../../util/fd_util.h"
#include "driver.h"
#include "../../disco/topo/fd_topob.h"
#include "../firedancer/topology.h"
#include "../firedancer/config.h"
#include "../shared_dev/boot/fd_dev_boot.h"
#include "../shared/commands/configure/configure.h"

int
main( int    argc,
      char** argv ) {
  if( FD_UNLIKELY( argc!=2 ) ) FD_LOG_ERR(( "usage: %s <topo_name>", argv[0] ));
  fd_drv_init( argv[1] );
  return 0;
}
