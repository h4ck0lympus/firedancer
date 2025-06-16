#include <stdlib.h>
#include "../../util/fd_util_base.h"
#include "driver.h"
#include "../shared/fd_action.h"


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
extern fd_topo_run_tile_t fd_tile_shred;
extern fd_topo_run_tile_t fd_tile_replay;

fd_topo_run_tile_t * TILES[] = {
    &fd_tile_gossip,
    &fd_tile_sign,
    &fd_tile_shred,
    &fd_tile_replay,
    NULL
};

/* I have no clue why the linker fails if these aren't there. */
action_t * ACTIONS[] = { NULL };

fd_drv_t * drv;


FD_FN_UNUSED static int
init( int  *   argc,
      char *** argv,
      char * topo_name ) {
  (void)argc; (void)argv;
  void * shmem = aligned_alloc( fd_drv_align(),  fd_drv_footprint() );
  if( FD_UNLIKELY( !shmem ) ) FD_LOG_ERR(( "malloc failed" ));
  drv = fd_drv_join( fd_drv_new( shmem, TILES, CALLBACKS ) );
  fd_drv_init( drv, topo_name );
  return 0;
}

/* define n bytes of data if the size is too small, return 1;
 otherwise set  */
#define CONSUME(n) (__extension__({        \
  uchar const * __x = data;                \
  if ( FD_UNLIKELY( size < n ) ) return 1; \
  size -= n;                               \
  data += n;                               \
  __x;                                     \
  }))

FD_FN_UNUSED static int
fuzz_gossip( uchar const * data,
             ulong         size ) {
  uchar should_call_housekeeping = *CONSUME(1);
  uchar is_backpressured = !(should_call_housekeeping % 4);
  /* this probability has no deeper justification, just put here for testing */
  if( FD_UNLIKELY( should_call_housekeeping > 25 ) ) {
    fd_drv_housekeeping( drv, "gossip", is_backpressured );
    /* we could consider calling sign's housekeeping here too, but
       it only does keyswitch right now. */
  }
  ulong net_sig = 5UL << 32UL;
  fd_drv_send( drv, "net", "gossip", 1, net_sig, (uchar *)data, 8 );
  return 0 /* Input succeeded.  Keep it if it found new coverage. */;
}

FD_FN_UNUSED static int
fuzz_shred( uchar const * data,
            ulong         size ) {
  // TODO replace with shred
  uchar should_call_housekeeping = *CONSUME(1);
  uchar is_backpressured = !(should_call_housekeeping % 4);
  /* this probability has no deeper justification, just put here for testing */
  if( FD_UNLIKELY( should_call_housekeeping > 25 ) ) {
    fd_drv_housekeeping( drv, "shred", is_backpressured );
  }
  ulong proto = 3UL;
  ulong sig = fd_disco_netmux_sig( 1245u, 768u, 0U, proto, 42 );
  /* we want the smallest possible header, which is 42 */
  if( FD_UNLIKELY( (size+42UL) > FD_NET_MTU ) ) {
    return 1;
  }
  fd_drv_send( drv, "net", "shred", 1UL, sig, (uchar *)data-42, size+42 );
  return 0 /* Input succeeded.  Keep it if it found new coverage. */;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  return fuzz_shred( data, size );
}

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  return init( argc, argv, "isolated_shred" );
}

#undef CONSUME
