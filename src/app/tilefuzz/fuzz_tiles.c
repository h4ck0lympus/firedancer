#include <stdlib.h>
#include "../../util/fd_util_base.h"
#include "driver.h"
#include "../shared/fd_action.h"
#include "../../disco/shred/fd_stake_ci.h"


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

// bitmap to keep unique pair of slot and parent slot for tower fuzzing
// one bit = one pair
static uchar seen[(MAX_FUNK_TXNS*MAX_FUNK_TXNS) >> 3]; // 4096 * 4096 / 8 (>> 3)

configure_stage_t * STAGES[] = {
  &fd_cfg_stage_hugetlbfs,
  NULL
};

fd_drv_t * drv;

// pair x parent_slot = 2d -> pair * MAX_FUNK_TXNS  + parent_slot (2d -> 1d)
static inline int pair_seen(ulong slot, ulong parent) {
    size_t idx = ((slot-1UL) * MAX_FUNK_TXNS + (parent-1UL));
    return seen[idx >> 3] &  (1u << (idx & 7));
}

static inline void mark_pair(ulong slot, ulong parent) {
    size_t idx = ((slot-1UL) * MAX_FUNK_TXNS + (parent-1UL));
    seen[idx >> 3] |= (1u << (idx & 7));
}

void reset_unique_pairs(void) {
    memset(seen, 0, sizeof(seen));
}

/* From HERE(1) just copied from stake ci tests consider moving to
   common place */

#define SLOTS_PER_EPOCH 1000 /* Just for testing */

static fd_stake_weight_msg_t *
generate_stake_msg( uchar *      _buf,
                    ulong        epoch,
                    char const * stakers ) {
  fd_stake_weight_msg_t *buf = fd_type_pun( _buf );

  buf->epoch          = epoch;
  buf->start_slot     = epoch * SLOTS_PER_EPOCH;
  buf->slot_cnt       = SLOTS_PER_EPOCH;
  buf->staked_cnt     = strlen(stakers);
  buf->excluded_stake = 0UL;

  ulong i = 0UL;
  for(; *stakers; stakers++, i++ ) {
    memset( buf->weights[i].key.uc, *stakers, sizeof(fd_pubkey_t) );
    buf->weights[i].stake = 1000UL/(i+1UL);
  }
  return fd_type_pun( _buf );
}

/* To HERE(1) */


FD_FN_UNUSED static int
init( int  *   argc,
      char *** argv,
      char * topo_name ) {
  (void)argc; (void)argv;
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_log_level_core_set(3);
  fd_boot(argc, argv);
  void * shmem = aligned_alloc( fd_drv_align(),  fd_drv_footprint() );
  if( FD_UNLIKELY( !shmem ) ) FD_LOG_ERR(( "malloc failed" ));
  drv = fd_drv_join( fd_drv_new( shmem, TILES, CALLBACKS, STAGES ) );
  fd_drv_init( drv, topo_name );
  /* setup stake ci for shred */
  if( 0==strcmp( "isolated_shred", topo_name ) ) {
    /* ehh, the api is not nice for this link */
    uchar stake_msg[ FD_STAKE_CI_STAKE_MSG_SZ ];
    generate_stake_msg( stake_msg, 0UL, "ABCDEF" );
    fd_drv_send( drv, "stake", "out", 2, 0UL, stake_msg, /* tight upper-bound okay */ FD_STAKE_CI_STAKE_MSG_SZ );
  }
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
  /* These probabilities have no deeper meaning.  Just put here for
     testing */
  uchar is_backpressured = !(should_call_housekeeping % 4);
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
  uchar should_call_housekeeping = *CONSUME(1);
  /* These probabilities have no deeper meaning.  Just put here for
     testing */
  uchar is_backpressured = !(should_call_housekeeping % 4);
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

FD_FN_UNUSED static int
fuzz_tower(uchar *data, 
           ulong size ) {
  // TODO : proper grammar fuzzing
  if (size < 2UL) return 1;

  uchar should_call_housekeeping = *CONSUME(1);
  /* These probabilities have no deeper meaning.  Just put here for
     testing */
  uchar is_backpressured = !(should_call_housekeeping % 4);
  if( FD_UNLIKELY( should_call_housekeeping > 25 ) ) {
    fd_drv_housekeeping( drv, "tower", is_backpressured );
  }
  // sig carries metadata and will decide what to do with data and how data is being processed
  // we need to fuzz tower so we will set sig to value that will make sure tower is called
  uchar gossip_sig_raw = *CONSUME(1);
  ulong gossip_sig = (gossip_sig_raw & 1U) ? fd_crds_data_enum_duplicate_shred /* 9 */
    : fd_crds_data_enum_vote; /*1 */

  ulong replay_sig_raw = *CONSUME(8);
  ulong parent_slot = (replay_sig_raw & 0xffffffff);
  ulong slot = replay_sig_raw >> 32;

  parent_slot = (parent_slot % MAX_FUNK_TXNS) + 1 ;
  slot = (slot % MAX_FUNK_TXNS) + 1;

  if (slot <= parent_slot) {
    slot = parent_slot + 1;
    if (slot > MAX_FUNK_TXNS) {
      slot = (slot % MAX_FUNK_TXNS) + 1;
      if (slot <= parent_slot) { 
        return 1; // no valid ordering found
      }
    }
  }

  if (pair_seen(slot, parent_slot)) {
    return 1;
  }

  mark_pair(slot, parent_slot);

  ulong replay_sig = ( slot << 32 ) | parent_slot;
  
  uchar *payload = data;
  ulong payload_sz = size;
  fd_drv_send( drv, "gossip", "tower", 1, gossip_sig, payload, payload_sz );
  fd_drv_send( drv, "gossip", "tower", 0, replay_sig, payload, payload_sz );

  return 0 /* Input succeeded.  Keep it if it found new coverage. */;
  
}

int
LLVMFuzzerTestOneInput( uchar * data,
                        ulong         size ) {
  return fuzz_tower( data, size );
}

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  return init( argc, argv, "isolated_tower" );
}

#undef CONSUME
