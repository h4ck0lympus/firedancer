#ifndef HEADER_fd_src_app_tilefuzz_driver_h
#define HEADER_fd_src_app_tilefuzz_driver_h

#include "../../disco/topo/fd_topob.h"
#include "../shared/fd_config.h"

struct fd_drv_private {
  fd_topo_run_tile_t **      tiles;
  fd_topo_obj_callbacks_t ** callbacks;
  fd_config_t                config;
};
typedef struct fd_drv_private fd_drv_t;

ulong
fd_drv_footprint( void );

FD_FN_CONST ulong
fd_drv_align( void );

void *
fd_drv_new( void * shmem, fd_topo_run_tile_t ** tiles, fd_topo_obj_callbacks_t ** callbacks );

fd_drv_t *
fd_drv_join( void * shmem );

void *
fd_drv_leave( fd_drv_t * drv );

void *
fd_drv_delete( void * shmem );

void
fd_drv_init( fd_drv_t * drv, char* topo_name );

void
fd_drv_housekeeping( fd_drv_t * drv, char * tile_name, int backpressured );

void
fd_drv_publish_hook( fd_frag_meta_t * mcache );

void
fd_drv_send( fd_drv_t * drv,
             char     * from,
             char     * to,
             ulong      in_idx,
             ulong      sig,
             uchar    * data,
             ulong      data_sz );
#endif /* HEADER_fd_src_app_tilefuzz_driver_h */
