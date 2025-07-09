#include "driver.h"
#include <stdlib.h>
#include <string.h>
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
extern fd_topo_obj_callbacks_t fd_obj_cb_funk;

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
    &fd_obj_cb_funk,
    NULL,
};

extern fd_topo_run_tile_t fd_tile_gossip;
extern fd_topo_run_tile_t fd_tile_shred;
extern fd_topo_run_tile_t fd_tile_sign;
extern fd_topo_run_tile_t fd_tile_replay;
extern fd_topo_run_tile_t fd_tile_tower;
extern fd_topo_run_tile_t fd_tile_send;

fd_topo_run_tile_t * TILES[] = {
  &fd_tile_gossip,
  &fd_tile_sign,
  &fd_tile_shred,
  &fd_tile_replay,
  &fd_tile_tower,
  &fd_tile_send,
  NULL
};
/* I have no clue why the linker fails if these aren't there. */
action_t * ACTIONS[] = { NULL };

int
main( int    argc,
      char** argv ) {
  fd_boot(&argc, &argv);
  if( FD_UNLIKELY( argc!=2 ) ) FD_LOG_ERR(( "usage: %s <topo_name>", argv[0] ));
  void * shmem = aligned_alloc( fd_drv_align(), fd_drv_footprint() );
  if( FD_UNLIKELY( !shmem ) ) FD_LOG_ERR(( "malloc failed" ));
  fd_drv_t * drv = fd_drv_join( fd_drv_new( shmem, TILES, CALLBACKS ) );
  if( FD_UNLIKELY( !drv ) ) FD_LOG_ERR(( "creating tile fuzz driver failed" ));
  fd_drv_init( drv, argv[1] );

  if( strcmp( argv[1], "isolated_gossip" ) == 0) {
    fd_drv_housekeeping( drv, "gossip", 0 );
    uchar * data = (uchar *) malloc( 8 );
    strcpy((char *) data, "ABCDEFG" );
    ulong net_sig = 5UL << 32UL;
    fd_drv_send( drv, "net", "gossip", 1, net_sig, data, 8 );
    free(data);
  } else if (strcmp( argv[1], "isolated_shred" ) == 0) {
    fd_drv_housekeeping( drv, "shred", 0 );
  } else if (strcmp(argv[1], "isolated_tower") == 0)  {
    fd_drv_housekeeping(drv, "tower", 0);
    uchar * data = (uchar *) malloc( 10 );
    strcpy((char *) data, "ABCDEFGH" );
    ulong raw_slot; memcpy(&raw_slot, data, 8);
    uint parent_slot = raw_slot & 0xffffffff;
    uint slot = (raw_slot >> 32) & 0xffffffff;

    parent_slot %= 0x1000;
    slot %= 0x1000;

    if (parent_slot > slot) {
      uint tmp = parent_slot;
      parent_slot = slot;
      slot = tmp;
    }

    ulong tower_slot_sig = ((ulong) slot << 32)  | parent_slot;
    fd_drv_send( drv, "gossip", "tower", 1, tower_slot_sig, data, 8 );
    free(data);
  } else {
    FD_LOG_ERR(( "unknown topo name" ));
  }
  
  free(shmem);
  return 0;
}
