#include "driver.h"
#include <stdlib.h>
#include "../shared/fd_action.h"

char const * FD_APP_NAME    = "fd_tile_fuzz";
char const * FD_BINARY_NAME = "fd_tile_fuzz";

extern fd_topo_obj_callbacks_t fd_obj_cb_mcache;
extern fd_topo_obj_callbacks_t fd_obj_cb_dcache;
extern fd_topo_obj_callbacks_t fd_obj_cb_cnc;
extern fd_topo_obj_callbacks_t fd_obj_cb_fseq;
extern fd_topo_obj_callbacks_t fd_obj_cb_metrics;
extern fd_topo_obj_callbacks_t fd_obj_cb_opaque;
extern fd_topo_obj_callbacks_t fd_obj_cb_dbl_buf;
extern fd_topo_obj_callbacks_t fd_obj_cb_neigh4_hmap;
extern fd_topo_obj_callbacks_t fd_obj_cb_fib4;
extern fd_topo_obj_callbacks_t fd_obj_cb_keyswitch;
extern fd_topo_obj_callbacks_t fd_obj_cb_tile;
extern fd_topo_obj_callbacks_t fd_obj_cb_runtime_pub;
extern fd_topo_obj_callbacks_t fd_obj_cb_blockstore;
extern fd_topo_obj_callbacks_t fd_obj_cb_txncache;
extern fd_topo_obj_callbacks_t fd_obj_cb_exec_spad;

fd_topo_obj_callbacks_t * CALLBACKS[] = {
    &fd_obj_cb_mcache,
    &fd_obj_cb_dcache,
    &fd_obj_cb_cnc,
    &fd_obj_cb_fseq,
    &fd_obj_cb_metrics,
    &fd_obj_cb_opaque,
    &fd_obj_cb_dbl_buf,
    &fd_obj_cb_neigh4_hmap,
    &fd_obj_cb_fib4,
    &fd_obj_cb_keyswitch,
    &fd_obj_cb_tile,
    &fd_obj_cb_runtime_pub,
    &fd_obj_cb_blockstore,
    &fd_obj_cb_txncache,
    &fd_obj_cb_exec_spad,
    NULL,
};

extern fd_topo_run_tile_t fd_tile_gossip;
extern fd_topo_run_tile_t fd_tile_sign;

fd_topo_run_tile_t * TILES[] = {
  &fd_tile_gossip,
  &fd_tile_sign,
  NULL
};
/* I have no clue why the linker fails if these aren't there. */
action_t * ACTIONS[] = { NULL };

int
main( int    argc,
      char** argv ) {
  if( FD_UNLIKELY( argc!=2 ) ) FD_LOG_ERR(( "usage: %s <topo_name>", argv[0] ));
  void * shmem = malloc( fd_drv_footprint() );
  if( FD_UNLIKELY( !shmem ) ) FD_LOG_ERR(( "malloc failed" ));
  fd_drv_t * drv = fd_drv_join( fd_drv_new( shmem, TILES, CALLBACKS ) );
  if( FD_UNLIKELY( !drv ) ) FD_LOG_ERR(( "creating tile fuzz driver failed" ));
  fd_drv_init( drv, argv[1] );
  fd_drv_housekeeping( drv, "gossip", 0 );
  uchar * data = (uchar *)malloc( 8 );
  strcpy( (char*)data, "ABCDEFG" );
  ulong net_sig = 5UL << 32UL;
  fd_drv_send( drv, "net", "gossip", 1, net_sig, data, 8 );
  return 0;
}
