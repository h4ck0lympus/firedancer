#ifndef HEADER_fd_src_app_tilefuzz_driver_h
#define HEADER_fd_src_app_tilefuzz_driver_h

#include "../../disco/topo/fd_topob.h"
#include "../shared/fd_config.h"

fd_config_t *
fd_drv_init( char* topo_name, fd_topo_obj_callbacks_t ** callbacks );

void
fd_drv_housekeeping( fd_topo_t * topo, fd_topo_tile_t * tile, fd_topo_run_tile_t ** tiles, int backpressured  );
#endif /* HEADER_fd_src_app_tilefuzz_driver_h */
