#include "driver.h"
#include <stdlib.h>
#include <string.h>
#include "../shared/fd_action.h"
#include "../shared/commands/configure/configure.h"
#include "../../flamenco/types/fd_types_custom.h"
#include "../../flamenco/types/fd_types.h"


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
extern fd_topo_obj_callbacks_t fd_obj_cb_blockstore;
extern fd_topo_obj_callbacks_t fd_obj_cb_txncache;
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
    &fd_obj_cb_blockstore,
    &fd_obj_cb_txncache,
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

configure_stage_t * STAGES[] = {
  &fd_cfg_stage_hugetlbfs,
  NULL
};

int
main( int    argc,
      char** argv ) {
  fd_boot(&argc, &argv);
  if( FD_UNLIKELY( argc!=2 ) ) FD_LOG_ERR(( "usage: %s <topo_name>", argv[0] ));
  void * shmem = aligned_alloc( fd_drv_align(), fd_drv_footprint() );
  if( FD_UNLIKELY( !shmem ) ) FD_LOG_ERR(( "malloc failed" ));
  fd_drv_t * drv = fd_drv_join( fd_drv_new( shmem, TILES, CALLBACKS, STAGES ) );
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
    
    // Create stake buffer with format: pubkey1 + stake1 + pubkey2 + stake2 + ...
    uchar stake_buffer[1024];
    ulong stake_offset = 0;
    
    // Add 6 validators (ABCDEF) with different stakes
    char stakers[] = "ABCDEF";
    for (ulong i = 0UL; i < 6UL; i++) {
      // Add pubkey (32 bytes filled with the character)
      memset(stake_buffer + stake_offset, stakers[i], sizeof(fd_pubkey_t));
      stake_offset += sizeof(fd_pubkey_t);
      
      // Add stake amount (8 bytes)
      ulong stake = 1000UL / (i + 1UL);
      memcpy(stake_buffer + stake_offset, &stake, sizeof(ulong));
      stake_offset += sizeof(ulong);
    }
    
    ulong sig = (1337UL << 32) | UINT_MAX; // parent_slot = SNAPSHOT_SLOT slot = 1337
    fd_drv_send( drv, "replay", "tower", 0, sig, stake_buffer, stake_offset );

    sig = (1338UL << 32) | 1337; // parent_slot = 1337 slot = 1338
    fd_drv_send( drv, "replay", "tower", 0, sig, NULL, 0 );

    sig = (1339UL << 32) | 1338; // parent_slot = 1338 slot = 1339
    fd_drv_send( drv, "replay", "tower", 0, sig, NULL, 0 );

    sig = (1340UL << 32) | 1338; // parent_slot = 1338 slot = 1340
    fd_drv_send( drv, "replay", "tower", 0, sig, NULL, 0 );

    sig = (1341UL << 32) | 1337; // parent_slot = 1337 slot = 1341
    fd_drv_send( drv, "replay", "tower", 0, sig, NULL, 0 );

    sig = (1342UL << 32) | 1341; // parent_slot = 1341 slot = 1342
    fd_drv_send( drv, "replay", "tower", 0, sig, NULL, 0 );
  } else {
    FD_LOG_ERR(( "unknown topo name" ));
  }
  
  free(shmem);
  return 0;
}
