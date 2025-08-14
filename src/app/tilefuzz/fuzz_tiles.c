#include <stdlib.h>
#include <string.h>
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


configure_stage_t * STAGES[] = {
  &fd_cfg_stage_hugetlbfs,
  NULL
};

fd_drv_t * drv;

/* From HERE(1) just copied from stake ci tests consider moving to
   common place */

#define SLOTS_PER_EPOCH 4096 /* Just for testing */

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
  //putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot(argc, argv);
  fd_log_level_logfile_set(0);
  fd_log_level_core_set(0);
  fd_log_level_stderr_set(0);
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

  // if( 0==strcmp( "isolated_tower", topo_name ) ) {
  //   /* ehh, the api is not nice for this link */
  //   uchar stake_msg[ FD_STAKE_CI_STAKE_MSG_SZ ];
  //   generate_stake_msg( stake_msg, 0UL, "ABCDEF" );
  //   fd_drv_send( drv, "stake", "out", 2, 0UL, stake_msg, /* tight upper-bound okay */ FD_STAKE_CI_STAKE_MSG_SZ );
  // }
  
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

// TODO make a fuzz ctx
static uint last_slot = UINT_MAX;

#define MAX_RECENT_PARENTS 4

static uchar used_slots[MAX_FUNK_TXNS];
static uint recently_added[MAX_RECENT_PARENTS];
static uchar num_recently_added = 0;
static uint ghost_root_slot = 0;

static uint next_unused_after(uint slot_start){ 
  for (uint s = slot_start; s < MAX_FUNK_TXNS; s++) {
    if (!used_slots[s]) {
      return s;
    }
  }
  // no slot found
  return UINT_MAX;
}


static void reset_state(void) {
  memset(used_slots, 0, sizeof(used_slots));
  memset(recently_added, 0, sizeof(recently_added));
  last_slot = UINT_MAX;
  num_recently_added = 0;
  ghost_root_slot = 0;
  used_slots[0] = 1;
}

int snapshot_slot_created = 0;
// rules: 
// parent slot for a slot should exist
// if a slot is used for voting, it cannot be used again unless ghost is reset or is used as a parent slot
// snapshot slot (ghost reset) should be sent and also needs to be simulated
// slot > parent slot
// slot < MAX_FUNK_TXNS
// we want to create slots/forks and let tower handle this 
FD_FN_UNUSED static int
fuzz_tower(uchar *data, 
           ulong size ) {
  if (size <= 4) return 1;
  
  static int ghost_initialized = 0;
  // TODO: check if we should we do grammar fuzzing?
  /* These probabilities have no deeper meaning.  Just put here for
     testing */
  uchar should_call_housekeeping = *CONSUME(1);
  uchar is_backpressured = !(should_call_housekeeping % 4);
  if( FD_UNLIKELY( should_call_housekeeping > 25 ) ) {
    fd_drv_housekeeping( drv, "tower", is_backpressured );
  }

  // sig carries metadata and will decide what to do with data and how data is being processed
  // we need to fuzz tower so we will set sig to value that will make sure tower is called
  uchar gossip_sig_raw = *CONSUME(1);
  ulong gossip_sig = (gossip_sig_raw & 1U) ? fd_crds_data_enum_duplicate_shred /* 9 */
    : fd_crds_data_enum_vote; /*1 */

  uchar* payload = data;
  ulong payload_sz = size;
  uint parent_slot;
  uint slot;

  ulong replay_sig;
  
  // send snapshot slot on first call to initialize ghost
  if (!ghost_initialized) {
    reset_state();
    // first send a snapshot slot to init ghost
    parent_slot = UINT_MAX;
    slot = (*CONSUME(2) & 0xfff) + 1;
    if (slot >= MAX_FUNK_TXNS) slot %= MAX_FUNK_TXNS;
    replay_sig = ((ulong) slot << 32) | parent_slot;
 
    // add 6 validators with random stake
    ulong total_stake = *(CONSUME(8));
    uchar stake_buffer[280]; // 32(pubkey) + 8(stake)
    ulong stake_offset = 0;
    uchar stake_msg[FD_STAKE_CI_STAKE_MSG_SZ];
    
    char stakers[] = "ABCDEF"; // 6 validators

    fd_stake_weight_msg_t *buf = fd_type_pun(stake_msg);

    buf->epoch = 0UL;
    buf->start_slot = 0;
    buf->slot_cnt = SLOTS_PER_EPOCH;
    buf->staked_cnt = strlen(stakers);
    buf->excluded_stake = 0UL;
    
    for (ulong i=0UL; i < 6UL; i++) {
      ulong stake = total_stake / (i + 1UL);

      // TODO: do we need to send message over link ? can't we just set the stake ?
      memset(buf->weights[i].key.uc, stakers[i], sizeof(fd_pubkey_t)); // pubkey bytearray
      buf->weights[i].stake = stake; // set validator stake

      memset(stake_buffer + stake_offset, stakers[i], sizeof(fd_pubkey_t));
      stake_offset += sizeof(fd_pubkey_t); // 32

      memcpy(stake_buffer + stake_offset, &stake, sizeof(ulong)); // set validator stake for stake out link
      stake_offset += sizeof(ulong);
    }

    fd_drv_send( drv, "stake", "out", 2, 0UL, stake_msg, /* tight upper-bound okay */ FD_STAKE_CI_STAKE_MSG_SZ );

    // fd_drv_send(drv, "gossip", "tower", 1, gossip_sig, payload, payload_sz);
    fd_drv_send(drv, "replay", "tower", 0, replay_sig, stake_buffer, stake_offset);

    // reset fuzzer state after snapshot
    memset(recently_added, 0, sizeof(recently_added));
    num_recently_added = 0;
    ghost_root_slot = slot;
    last_slot = slot;
    if (slot < MAX_FUNK_TXNS) {
      used_slots[slot] = 1;
    }
    recently_added[0] = slot;
    num_recently_added = 1;
    
    snapshot_slot_created = 1;
    ghost_initialized = 1;
    FD_LOG_NOTICE(("parent_slot: SNAPSHOT slot: %u", slot));
  }

  while (size > 4) {
    uint make_fork = (*CONSUME(1) < 64);

    if (make_fork) {
      if (!num_recently_added) break;
      uint idx = (*CONSUME(1)) % num_recently_added;
      parent_slot = recently_added[idx];
      // ensure parent slot is valid - must be >= ghost_root_slot
      if (parent_slot < ghost_root_slot) {
        parent_slot = last_slot;
      }
    } else {
      parent_slot = last_slot;
    }
    
    // ensure parent_slot is always >= ghost_root_slot
    if (parent_slot < ghost_root_slot) {
      parent_slot = ghost_root_slot;
    }

    uint gap = *CONSUME(1) & 0xf + 1;
    uint candidate = parent_slot + gap;
    slot = next_unused_after(candidate);
    if (slot == UINT_MAX || slot <= parent_slot) return 1;
    if (used_slots[slot]) return 1;

    FD_LOG_NOTICE(("parent_slot: %u slot: %u", parent_slot, slot));
    replay_sig = ((ulong)slot << 32) | parent_slot;
    fd_drv_send(drv, "gossip", "tower", 1, gossip_sig, payload, payload_sz);
    fd_drv_send(drv, "replay", "tower", 0, replay_sig, payload, payload_sz);
    used_slots[slot] = 1;
    recently_added[num_recently_added % MAX_RECENT_PARENTS] = slot;
    num_recently_added++;
    last_slot = slot;
  }
  return 0;
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
