#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "../../disco/topo/fd_topob.h"
#include "../../util/pod/fd_pod_format.h"
#include "../../disco/metrics/fd_metrics.h"
#include "driver.h"
#include "../../disco/net/fd_net_tile.h" /* fd_topos_net_tiles */
#include "../../flamenco/snapshot/fd_snapshot_loader.h" /* FD_SNAPSHOT_SRC_HTTP */

#include <sys/random.h>
#include <sys/stat.h> /* mkdir */

// TODO consider making this more like an FD object with new, join, ...

extern fd_topo_run_tile_t fd_tile_gossip;
extern fd_topo_run_tile_t fd_tile_shred;
extern fd_topo_run_tile_t fd_tile_sign;
extern fd_topo_run_tile_t fd_tile_replay;
extern fd_topo_run_tile_t fd_tile_tower;
extern fd_topo_run_tile_t fd_tile_send;

FD_FN_CONST ulong
fd_drv_footprint( void ) {
  return sizeof(fd_drv_t);
}

FD_FN_CONST ulong
fd_drv_align( void ) {
  return alignof(fd_drv_t);
}

void *
fd_drv_new( void * shmem, fd_topo_run_tile_t ** tiles, fd_topo_obj_callbacks_t ** callbacks ) {
  fd_drv_t * drv = (fd_drv_t *)shmem;
  drv->tiles = tiles;
  drv->callbacks = callbacks;
  drv->config = (fd_config_t){0};
  return drv;
}

fd_drv_t *
fd_drv_join( void * shmem ) {
  return (fd_drv_t *) shmem;
}

void *
fd_drv_leave( fd_drv_t * drv ) {
  return (void *) drv;
}

void *
fd_drv_delete( void * shmem ) {
  // TODO dealoc obj mem
  return shmem;
}


void
fd_drv_publish_hook( fd_frag_meta_t const * mcache ) {
  FD_LOG_NOTICE(( "fd_drv_publish_hook received chunk of size %u", mcache->sz ));
  /* relay to another tile using the send function, validate data, or
     ignore */
}


static void create_tmp_file( char const * path, char const * content ) {
  int fd = open( path, O_RDWR|O_CREAT|O_TRUNC, 0644 );
  if( FD_UNLIKELY( fd<0 ) ) FD_LOG_ERR(( "open failed" ));
  long sz = write( fd, content, strlen( content ) );
  if( FD_UNLIKELY( sz<0 ) ) {
    close( fd );
    FD_LOG_ERR(( "write failed" ));
  }
  close( fd );
}

// taken from firedancer/topology.c
// technically can be made non static and well inluded but i don't want to break anything
// so doing minimal changes in firedancer code
FD_FN_UNUSED static void
setup_snapshots( config_t *       config,
                 fd_topo_tile_t * tile ) {
  uchar incremental_is_file, incremental_is_url;
  if( strnlen( config->tiles.replay.incremental, PATH_MAX )>0UL ) {
    incremental_is_file = 1U;
  } else {
    incremental_is_file = 0U;
  }
  if( strnlen( config->tiles.replay.incremental_url, PATH_MAX )>0UL ) {
    incremental_is_url = 1U;
  } else {
    incremental_is_url = 0U;
  }
  if( FD_UNLIKELY( incremental_is_file && incremental_is_url ) ) {
    FD_LOG_ERR(( "At most one of the incremental snapshot source strings in the configuration file under [tiles.replay.incremental] and [tiles.replay.incremental_url] may be set." ));
  }
  tile->replay.incremental_src_type = INT_MAX;
  if( FD_LIKELY( incremental_is_url ) ) {
    strncpy( tile->replay.incremental, config->tiles.replay.incremental_url, sizeof(tile->replay.incremental) );
    tile->replay.incremental_src_type = FD_SNAPSHOT_SRC_HTTP;
  }
  if( FD_UNLIKELY( incremental_is_file ) ) {
    strncpy( tile->replay.incremental, config->tiles.replay.incremental, sizeof(tile->replay.incremental) );
    tile->replay.incremental_src_type = FD_SNAPSHOT_SRC_FILE;
  }
  tile->replay.incremental[ sizeof(tile->replay.incremental)-1UL ] = '\0';

  uchar snapshot_is_file, snapshot_is_url;
  if( strnlen( config->tiles.replay.snapshot, PATH_MAX )>0UL ) {
    snapshot_is_file = 1U;
  } else {
    snapshot_is_file = 0U;
  }
  if( strnlen( config->tiles.replay.snapshot_url, PATH_MAX )>0UL ) {
    snapshot_is_url = 1U;
  } else {
    snapshot_is_url = 0U;
  }
  if( FD_UNLIKELY( snapshot_is_file && snapshot_is_url ) ) {
    FD_LOG_ERR(( "At most one of the full snapshot source strings in the configuration file under [tiles.replay.snapshot] and [tiles.replay.snapshot_url] may be set." ));
  }
  tile->replay.snapshot_src_type = INT_MAX;
  if( FD_LIKELY( snapshot_is_url ) ) {
    strncpy( tile->replay.snapshot, config->tiles.replay.snapshot_url, sizeof(tile->replay.snapshot) );
    tile->replay.snapshot_src_type = FD_SNAPSHOT_SRC_HTTP;
  }
  if( FD_UNLIKELY( snapshot_is_file ) ) {
    strncpy( tile->replay.snapshot, config->tiles.replay.snapshot, sizeof(tile->replay.snapshot) );
    tile->replay.snapshot_src_type = FD_SNAPSHOT_SRC_FILE;
  }
  tile->replay.snapshot[ sizeof(tile->replay.snapshot)-1UL ] = '\0';

  strncpy( tile->replay.snapshot_dir, config->tiles.replay.snapshot_dir, sizeof(tile->replay.snapshot_dir) );
  tile->replay.snapshot_dir[ sizeof(tile->replay.snapshot_dir)-1UL ] = '\0';
}

FD_FN_UNUSED static fd_topo_obj_t *
setup_topo_txncache( fd_topo_t *  topo,
                    char const * wksp_name,
                    ulong        max_rooted_slots,
                    ulong        max_live_slots,
                    ulong        max_txn_per_slot,
                    ulong        max_constipated_slots ) {
  fd_topo_obj_t * obj = fd_topob_obj( topo, "txncache", wksp_name );

  FD_TEST( fd_pod_insertf_ulong( topo->props, max_rooted_slots, "obj.%lu.max_rooted_slots", obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, max_live_slots,   "obj.%lu.max_live_slots",   obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, max_txn_per_slot, "obj.%lu.max_txn_per_slot", obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, max_constipated_slots, "obj.%lu.max_constipated_slots", obj->id ) );

  return obj;
}

FD_FN_UNUSED static fd_topo_obj_t *
setup_topo_blockstore( fd_topo_t *  topo,
                      char const * wksp_name,
                      ulong        shred_max,
                      ulong        block_max,
                      ulong        idx_max,
                      ulong        txn_max,
                      ulong        alloc_max ) {
  fd_topo_obj_t * obj = fd_topob_obj( topo, "blockstore", wksp_name );

  ulong seed;
  FD_TEST( sizeof(ulong) == getrandom( &seed, sizeof(ulong), 0 ) );

  FD_TEST( fd_pod_insertf_ulong( topo->props, 1UL,        "obj.%lu.wksp_tag",   obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, seed,       "obj.%lu.seed",       obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, shred_max,  "obj.%lu.shred_max",  obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, block_max,  "obj.%lu.block_max",  obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, idx_max,    "obj.%lu.idx_max",    obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, txn_max,    "obj.%lu.txn_max",    obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, alloc_max,  "obj.%lu.alloc_max",  obj->id ) );

  /* DO NOT MODIFY LOOSE WITHOUT CHANGING HOW BLOCKSTORE ALLOCATES INTERNAL STRUCTURES */

  ulong blockstore_footprint = fd_blockstore_footprint( shred_max, block_max, idx_max, txn_max ) + alloc_max;
  FD_TEST( fd_pod_insertf_ulong( topo->props, blockstore_footprint,  "obj.%lu.loose", obj->id ) );

  return obj;
}

fd_topo_obj_t *
setup_topo_runtime_pub( fd_topo_t *  topo,
                        char const * wksp_name,
                        ulong        mem_max ) {
  fd_topo_obj_t * obj = fd_topob_obj( topo, "runtime_pub", wksp_name );
  FD_TEST( fd_pod_insertf_ulong( topo->props, mem_max, "obj.%lu.mem_max",  obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, 12UL,    "obj.%lu.wksp_tag", obj->id ) );
  return obj;
}

fd_topo_obj_t *
setup_topo_funk( fd_topo_t *  topo,
                 char const * wksp_name,
                 ulong        max_account_records,
                 ulong        max_database_transactions,
                 ulong        heap_size_gib ) {
  fd_topo_obj_t * obj = fd_topob_obj( topo, "funk", wksp_name );
  FD_TEST( fd_pod_insert_ulong(  topo->props, "funk", obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, max_account_records,       "obj.%lu.rec_max",  obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, max_database_transactions, "obj.%lu.txn_max",  obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, heap_size_gib*(1UL<<30),   "obj.%lu.heap_max", obj->id ) );
  ulong funk_footprint = fd_funk_footprint( max_database_transactions, max_account_records );
  if( FD_UNLIKELY( !funk_footprint ) ) FD_LOG_ERR(( "Invalid [funk] parameters" ));

    /* Increase workspace partition count */
  ulong wksp_idx = fd_topo_find_wksp( topo, wksp_name );
  FD_TEST( wksp_idx!=ULONG_MAX );
  fd_topo_wksp_t * wksp = &topo->workspaces[ wksp_idx ];
  ulong part_max = fd_wksp_part_max_est( funk_footprint, 1U<<14U );
  if( FD_UNLIKELY( !part_max ) ) FD_LOG_ERR(( "fd_wksp_part_max_est(%lu,16KiB) failed", funk_footprint ));
  wksp->part_max += part_max;

  return obj;
}

FD_FN_UNUSED static fd_topo_tile_t*
init_replay_tile(fd_topo_t* topo, config_t* config) {
  fd_topo_tile_t* replay_tile = fd_topob_tile(topo, "replay", "replay", "metric_in", 0, 0, 0);

    replay_tile->replay.fec_max = config->tiles.shred.max_pending_shred_sets;
    replay_tile->replay.max_vote_accounts = config->firedancer.runtime.limits.max_vote_accounts;

    strncpy( replay_tile->replay.blockstore_file,    config->firedancer.blockstore.file,    sizeof(replay_tile->replay.blockstore_file) );
    strncpy( replay_tile->replay.blockstore_checkpt, config->firedancer.blockstore.checkpt, sizeof(replay_tile->replay.blockstore_checkpt) );

    replay_tile->replay.tx_metadata_storage = config->rpc.extended_tx_metadata_storage;
    strncpy( replay_tile->replay.funk_checkpt, config->tiles.replay.funk_checkpt, sizeof(replay_tile->replay.funk_checkpt) );

    replay_tile->replay.funk_obj_id = fd_pod_query_ulong( config->topo.props, "funk", ULONG_MAX );
    replay_tile->replay.plugins_enabled = fd_topo_find_tile( &config->topo, "plugin", 0UL ) != ULONG_MAX;

    if( FD_UNLIKELY( !strncmp( config->tiles.replay.genesis,  "", 1 )
                  && !strncmp( config->tiles.replay.snapshot, "", 1 ) ) ) {
      fd_cstr_printf_check( config->tiles.replay.genesis, PATH_MAX, NULL, "%s/genesis.bin", config->paths.ledger );
    }
    strncpy( replay_tile->replay.genesis, config->tiles.replay.genesis, sizeof(replay_tile->replay.genesis) );

    strncpy( replay_tile->replay.slots_replayed, config->tiles.replay.slots_replayed, sizeof(replay_tile->replay.slots_replayed) );
    strncpy( replay_tile->replay.status_cache, config->tiles.replay.status_cache, sizeof(replay_tile->replay.status_cache) );
    strncpy( replay_tile->replay.cluster_version, config->tiles.replay.cluster_version, sizeof(replay_tile->replay.cluster_version) );
    strncpy( replay_tile->replay.tower_checkpt, config->tiles.replay.tower_checkpt, sizeof(replay_tile->replay.tower_checkpt) );


    strncpy( replay_tile->replay.identity_key_path, config->paths.identity_key, sizeof(replay_tile->replay.identity_key_path) );
    replay_tile->replay.ip_addr = config->net.ip_addr;
    strncpy( replay_tile->replay.vote_account_path, config->paths.vote_account, sizeof(replay_tile->replay.vote_account_path) );
    replay_tile->replay.enable_bank_hash_cmp = 1;

    replay_tile->replay.capture_start_slot = config->capture.capture_start_slot;
    strncpy( replay_tile->replay.solcap_capture, config->capture.solcap_capture, sizeof(replay_tile->replay.solcap_capture) );
    strncpy( replay_tile->replay.dump_proto_dir, config->capture.dump_proto_dir, sizeof(replay_tile->replay.dump_proto_dir) );
    replay_tile->replay.dump_block_to_pb = config->capture.dump_block_to_pb;

    FD_TEST( replay_tile->replay.funk_obj_id == fd_pod_query_ulong( config->topo.props, "funk", ULONG_MAX ) );

  return replay_tile;
}

static fd_topo_tile_t*
init_gossip_tile(fd_topo_t* topo, config_t* config) {

  fd_topo_tile_t * gossip_tile = fd_topob_tile( topo, "gossip", "gossip", "metric_in", 0UL, 0, 0 );

  strncpy( gossip_tile->gossip.identity_key_path, config->paths.identity_key, sizeof(gossip_tile->gossip.identity_key_path) );
  gossip_tile->gossip.gossip_listen_port     = 42;
  gossip_tile->gossip.ip_addr                = (uint)(1<<24 | 1<<16 | 1<<8 | 1);
  gossip_tile->gossip.expected_shred_version = 50093UL;
  gossip_tile->gossip.entrypoints_cnt = FD_TOPO_GOSSIP_ENTRYPOINTS_MAX;
  FD_STATIC_ASSERT( FD_TOPO_GOSSIP_ENTRYPOINTS_MAX<256UL-2UL, "dummy address encoding scheme only works for 8-bit" );
  for( uchar i=2; i<FD_TOPO_GOSSIP_ENTRYPOINTS_MAX; i++ ) {
    gossip_tile->gossip.entrypoints[i].addr = (uint)(i<<24 | i<<16 | i<<8 | i);
    gossip_tile->gossip.entrypoints[i].port = i;
  }

  fd_topob_wksp( topo, "sign" );
  fd_topo_tile_t * sign_tile = fd_topob_tile( topo, "sign", "sign", "metric_in", 0UL, 0, 1 );
  strncpy( sign_tile->sign.identity_key_path, config->paths.identity_key, sizeof(sign_tile->sign.identity_key_path) );

  fd_topob_wksp    ( topo, "gossip_sign" );
  fd_topob_link    ( topo, "gossip_sign", "gossip_sign", 128UL, 2048UL, 1UL );
  fd_topob_tile_in ( topo, "sign", 0UL, "metric_in", "gossip_sign", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  fd_topob_wksp    ( topo, "sign_gossip" );
  fd_topob_link    ( topo, "sign_gossip", "sign_gossip", 128UL, 64UL, 1UL );
  fd_topob_tile_out( topo, "sign", 0UL, "sign_gossip", 0UL );
  fd_topob_tile_in ( topo, "gossip", 0UL, "metric_in", "sign_gossip",  0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
  fd_topob_tile_out( topo, "gossip", 0UL, "gossip_sign", 0UL );

  fd_topob_wksp    ( topo, "net_gossip" );
  fd_topob_link    ( topo, "net_gossip", "net_gossip", 128UL, 2048UL, 1UL ); // TODO check params
  fd_topob_tile_in ( topo, "gossip", 0UL, "metric_in", "net_gossip",   0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );

  fd_topo_obj_t * poh_shred_obj = fd_topob_obj( topo, "fseq", "gossip" );
  FD_TEST( fd_pod_insertf_ulong( topo->props, poh_shred_obj->id, "poh_shred" ) );
  fd_topob_tile_uses( topo, gossip_tile, poh_shred_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  return gossip_tile;
}

FD_FN_UNUSED static fd_topo_tile_t*
init_send_tile(fd_topo_t* topo, config_t* config) {
  fd_topob_wksp(topo, "send");
  fd_topob_wksp(topo, "send_net");  
  fd_topob_wksp(topo, "send_txns");  
  fd_topob_wksp(topo, "tower_send");
  fd_topob_wksp(topo, "gossip_send");
  fd_topob_wksp(topo, "send_sign");  
  fd_topob_wksp(topo, "sign_send");
  fd_topob_wksp(topo, "stake_out");
  // ~imo we don't need tower send~  --- ok we needed tower send
  fd_topo_tile_t* send_tile = fd_topob_tile( topo, "send", "send", "metric_in", 0, 0, 0);
  strncpy(send_tile->send.identity_key_path, config->paths.identity_key, sizeof(send_tile->send.identity_key_path));

  fd_topob_link(topo, "gossip_send", "gossip_send", 128UL, 40200UL * 38UL, 1UL);
  fd_topob_link(topo, "tower_send", "tower_send", 65536UL, sizeof(fd_txn_p_t), 1UL);
  fd_topob_link(topo, "send_net", "send_net", 128UL, 2048UL, 1UL);  
  fd_topob_link(topo, "send_sign", "send_sign", 128UL, 64UL, 1UL);  
  fd_topob_link(topo, "send_txns", "send_txns",  128UL, FD_TXN_MTU, 1UL);
  fd_topob_link(topo, "sign_send", "sign_send", 128UL, 64UL, 1UL);  
  fd_topob_link(topo, "stake_out", "stake_out", 128UL, 40UL + 40200UL * 40UL, 1UL);  

  fd_topob_tile_in(topo, "send", 0UL, "metric_in", "stake_out", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED);
  fd_topob_tile_in(topo, "send", 0UL, "metric_in", "gossip_send", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED);
  fd_topob_tile_in(topo, "send", 0UL, "metric_in", "tower_send", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED);  
  fd_topob_tile_in(topo, "send", 0UL, "metric_in", "sign_send", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED);
  fd_topob_tile_in(topo, "gossip",  0UL, "metric_in", "send_txns" , 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED);

  fd_topob_tile_out(topo, "gossip", 0UL, "gossip_send", 0UL);
  fd_topob_tile_out(topo, "send", 0UL, "send_net", 0UL);  
  fd_topob_tile_out(topo, "send", 0UL, "send_sign", 0UL);
  fd_topob_tile_out(topo, "tower", 0UL, "tower_send",0UL);
  fd_topob_tile_out(topo, "send", 0UL, "send_txns",0UL);

  return send_tile;
}

static void
isolated_tower_topo(config_t* config, fd_topo_obj_callbacks_t* callbacks[])
{
  fd_topo_t * topo = &config->topo;
  fd_topob_new( &config->topo, config->name );

  // create necessary workspaces
  fd_topob_wksp(topo, "metric_in");
  fd_topob_wksp(topo, "tower");
  fd_topob_wksp(topo, "gossip_tower");
  fd_topob_wksp(topo, "gossip");
  fd_topob_wksp(topo, "replay_tower");
  fd_topob_wksp(topo, "replay");
 
  // creating links
  fd_topob_link(topo, "gossip_tower", "gossip_tower", 128UL, FD_TPU_MTU, 1UL );
  fd_topob_link(topo, "replay_tower", "replay_tower", 128UL, 65536UL, 1UL );
  fd_topob_link(topo, "tower_replay", "replay_tower", 128UL, 0, 1UL );

  // create tower tile
  fd_topo_tile_t* tower_tile = fd_topob_tile(topo, "tower", "tower", "metric_in", 0, 0, 0);

  config->firedancer.funk.max_account_records = 1000000;  
  config->firedancer.funk.max_database_transactions = 1024;  
  config->firedancer.funk.heap_size_gib = 1;

  //TODO funk setup
  fd_topob_wksp(topo, "funk");
  fd_topo_obj_t * funk_obj = setup_topo_funk( topo, "funk",
      config->firedancer.funk.max_account_records,
      config->firedancer.funk.max_database_transactions,
      config->firedancer.funk.heap_size_gib 
    );
  
  // do necessary config required by tower
  tower_tile->tower.funk_obj_id = fd_pod_query_ulong( config->topo.props, "funk", ULONG_MAX );
  strncpy(tower_tile->tower.identity_key_path, config->paths.identity_key, sizeof(tower_tile->tower.identity_key_path));
  strncpy(tower_tile->tower.vote_acc_path, config->paths.vote_account, sizeof(tower_tile->tower.vote_acc_path));
 
  // tower requires initialization of gossip tile and replay tile
  init_gossip_tile(topo, config);
  fd_topo_tile_t* replay_tile = init_replay_tile(topo, config);
  
  init_send_tile(topo, config);

  fd_topob_tile_in(topo, "tower", 0UL, "metric_in", "gossip_tower", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED);
  fd_topob_tile_in(topo, "tower",   0UL, "metric_in", "replay_tower", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED);
  fd_topob_tile_out(topo, "tower", 0UL, "tower_replay", 0UL);
  fd_topob_tile_out(topo, "gossip", 0UL, "gossip_tower", 0UL);

  fd_topob_tile_in(topo, "replay",  0UL, "metric_in", "tower_replay",  0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED);
  fd_topob_tile_out(topo, "replay", 0UL, "replay_tower", 0UL);

  fd_topob_wksp(topo, "slot_fseqs");
  fd_topo_obj_t* root_slot_obj = fd_topob_obj(topo, "fseq", "slot_fseqs");
  fd_topob_tile_uses(topo, tower_tile, root_slot_obj, FD_SHMEM_JOIN_MODE_READ_WRITE);
  FD_TEST(fd_pod_insertf_ulong(topo->props, root_slot_obj->id, "root_slot"));
  
  fd_topo_obj_t * turbine_slot0_obj = fd_topob_obj( topo, "fseq", "slot_fseqs" );
  fd_topob_tile_uses( topo, replay_tile, turbine_slot0_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  FD_TEST( fd_pod_insertf_ulong( topo->props, turbine_slot0_obj->id, "turbine_slot0" ) );

  fd_topo_obj_t * turbine_slot_obj = fd_topob_obj( topo, "fseq", "slot_fseqs" );
  fd_topob_tile_uses( topo, replay_tile, turbine_slot_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  FD_TEST( fd_pod_insertf_ulong( topo->props, turbine_slot_obj->id, "turbine_slot" ) );

  fd_topob_tile_uses( topo, replay_tile,  funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topob_finish(topo, callbacks);
}


// TODO do code style linting pass
/* This is a minimal implementation of starting the gossip tile.  With
   this a few parts of the gossip code won't be exercised, as they check
   for the existence of the optional links. */
static void
isolated_gossip_topo( config_t * config, fd_topo_obj_callbacks_t * callbacks[] ) {
  fd_topo_t * topo = &config->topo;
  fd_topob_new( &config->topo, config->name );
  // topo->max_page_size = 4096UL;
  
  fd_topob_wksp( topo, "metric_in" );
  fd_topob_wksp( topo, "gossip" );
  init_gossip_tile(topo, config);

  fd_topob_finish( topo, callbacks );
}

static void
isolated_shred_topo( config_t * config, fd_topo_obj_callbacks_t * callbacks[] ) {
  fd_topo_t * topo = &config->topo;
  fd_topob_new( &config->topo, config->name );
  fd_topob_wksp( topo, "metric_in" );
  fd_topob_wksp( topo, "shred" );
  fd_topo_tile_t * shred_tile = fd_topob_tile( topo, "shred", "shred", "metric_in", 0UL, 0, 0 );

  strncpy( shred_tile->shred.identity_key_path, config->paths.identity_key, sizeof(shred_tile->shred.identity_key_path) );
  shred_tile->shred.depth = 1UL;
  /* We might not need so much for testing, but this is the default.
     If we ever want to save memory, then consider lowering it. */
  config->tiles.shred.max_pending_shred_sets = 16384; // 2^14
  shred_tile->shred.fec_resolver_depth = config->tiles.shred.max_pending_shred_sets;
  shred_tile->shred.expected_shred_version = config->consensus.expected_shred_version;
  shred_tile->shred.shred_listen_port = 123;
  shred_tile->shred.larger_shred_limits_per_block = 0;
  shred_tile->shred.adtl_dest.ip = 123;
  shred_tile->shred.adtl_dest.port = 123;
  shred_tile->shred.depth = 65536UL;

  /* TODO setup all fake links
    - shred_store
    - shred_net
    - shred_sign
    - sign_shred
    The following are semi-optional
    - net_shred
    - poh_shred
    - stake_out
    - crds_shred
    - sign_shred
    - repair_shred
  */

  /* TODO explore using less memory for the tiles that are purely
          mocks */
  /* TODO explore saving memory by using just one wksp for all links */
  fd_topob_wksp    ( topo, "shred_store" );
  fd_topob_link( topo, "shred_store",  "shred_store",  65536UL, 4UL*FD_SHRED_STORE_MTU, 4UL+config->tiles.shred.max_pending_shred_sets );
  fd_topob_tile_out( topo, "shred", 0UL, "shred_store", 0UL );

  fd_topob_wksp    ( topo, "shred_net" );
  fd_topob_link    ( topo, "shred_net",  "shred_net", 128UL, 2048UL, 1UL );
  fd_topob_tile_out( topo, "shred", 0UL, "shred_net", 0UL );

  fd_topob_wksp( topo, "sign" );
  fd_topo_tile_t * sign_tile = fd_topob_tile( topo, "sign", "sign", "metric_in", 0UL, 0, 1 );
  strncpy( sign_tile->sign.identity_key_path, config->paths.identity_key, sizeof(sign_tile->sign.identity_key_path) );

  fd_topob_wksp    ( topo, "shred_sign" );
  fd_topob_link    ( topo, "shred_sign", "shred_sign", 128UL, 32UL, 1UL );
  fd_topob_tile_in ( topo, "sign", 0UL, "metric_in", "shred_sign", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );

  fd_topob_wksp    ( topo, "sign_shred" );
  fd_topob_link    ( topo, "sign_shred", "sign_shred", 128UL, 64UL, 1UL );
  fd_topob_tile_out( topo, "sign", 0UL, "sign_shred", 0UL );
  fd_topob_tile_in ( topo, "shred", 0UL, "metric_in", "sign_shred",  0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
  fd_topob_tile_out( topo, "shred", 0UL, "shred_sign", 0UL );
  /* I don't think we need sign in for this topology right now, but not
     sure.  Recheck, when we have mcache_publish hooking, and shred
     needs verify. */

  fd_topob_wksp    ( topo, "net_shred" );
  fd_topob_link    ( topo, "net_shred", "net_shred", 128UL, 2048UL, 1UL ); // TODO check params
  fd_topob_tile_in ( topo, "shred", 0UL, "metric_in", "net_shred",   0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );

  /* aka stake_out */
  fd_topob_wksp    ( topo, "stake_out" );
  fd_topob_link    ( topo, "stake_out", "stake_out", 128UL, 40UL + 40200UL * 40UL, 1UL );
  fd_topob_tile_in ( topo, "shred",  0UL, "metric_in", "stake_out", 0UL, FD_TOPOB_RELIABLE,     FD_TOPOB_POLLED );

  fd_topob_wksp    ( topo, "crds_shred" );
  fd_topob_link    ( topo, "crds_shred", "crds_shred", 128UL, 8UL + 40200UL * 38UL, 1UL );
  fd_topob_tile_in ( topo, "shred", 0, "metric_in", "crds_shred", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

  /* mock for  `  if( FD_UNLIKELY( !bank_cnt && !replay_cnt ) ) FD_LOG_ERR(( "0 bank/replay tiles" )); */
  fd_topob_wksp    ( topo, "replay" );
  fd_topo_tile_t * replay_tile = fd_topob_tile( topo, "replay", "replay", "metric_in", 0UL, 0, 1 );
  (void)replay_tile;

  fd_topob_finish( topo, callbacks );
}

/* Maybe similar to what initialize workspaces does, without
   following it closely */
// TODO: can we share wksp between different objects?
static void
back_wksps( fd_topo_t * topo, fd_topo_obj_callbacks_t * callbacks[] ) {
  ulong keyswitch_obj_id = ULONG_MAX;
  for( ulong i=0UL; i<topo->obj_cnt; i++ ) {
    fd_topo_obj_t * obj = &topo->objs[ i ];
    fd_topo_obj_callbacks_t * cb = NULL;
    for( ulong j=0UL; callbacks[ j ]; j++ ) {
      if( FD_UNLIKELY( !strcmp( callbacks[ j ]->name, obj->name ) ) ) {
        cb = callbacks[ j ];
        break;
      }
    }
    ulong align = cb->align( topo, obj );
    ulong page_cnt = 1;
    char* _page_sz = "gigantic";
    ulong numa_idx = fd_shmem_numa_idx(0);

    FD_LOG_NOTICE( ( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)", page_cnt, _page_sz, numa_idx ) );

    static int wksp_idx = 0;
    char wksp_name[64];  
    snprintf(wksp_name, sizeof(wksp_name), "wksp_%d", wksp_idx);
    wksp_idx++;

    fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ),
                                            page_cnt,
                                            fd_shmem_cpu_idx(numa_idx),
                                            wksp_name,
                                            0UL );
    FD_TEST(wksp);

    obj->wksp_id = obj->id;
    topo->workspaces[ obj->wksp_id ].wksp = wksp; // aligned_alloc( align, obj->footprint );
    // obj->offset = 0UL;
    FD_LOG_NOTICE(( "obj %s %lu %lu %lu %lu", obj->name, obj->wksp_id, obj->footprint, obj->offset, align ));
    FD_LOG_NOTICE(( "wksp pointer %p", (void*)topo->workspaces[ obj->wksp_id ].wksp ));
    /* ~equivalent to fd_topo_wksp_new in a world of real workspaces */
    if( FD_UNLIKELY( cb->new ) ) { /* only saw this null for tiles */
      cb->new( topo, obj );
    }
    if( FD_UNLIKELY( 0== strcmp( obj->name, "keyswitch" ) ) ) {
      keyswitch_obj_id = obj->id;
    }
    // TODO add ASAN and MSAN poisoned memory before and after
  }

  /* The rest of this function an adoption of fd_topo_wksp_fill without
     the wksp id checks.  I haven't looked into why they are needed */
  for( ulong i=0UL; i<topo->link_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ i ];
    link->mcache = fd_mcache_join( fd_topo_obj_laddr( topo, link->mcache_obj_id ) );
#ifdef FD_HAS_FUZZ /* TODO now basically everything needs FUZZ */
    link->mcache->hook = fd_drv_publish_hook;
#endif
    FD_TEST( link->mcache );
    /* only saw this false for tile code */
    if( FD_LIKELY( link->mtu ) ) {
      link->dcache = fd_dcache_join( fd_topo_obj_laddr( topo, link->dcache_obj_id ) );
      FD_TEST( link->dcache );
    }
  }

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    tile->keyswitch_obj_id = keyswitch_obj_id;

    tile->metrics = fd_metrics_join( fd_topo_obj_laddr( topo, tile->metrics_obj_id ) );
    FD_TEST( tile->metrics );

    for( ulong j=0UL; j<tile->in_cnt; j++ ) {
      tile->in_link_fseq[ j ] = fd_fseq_join( fd_topo_obj_laddr( topo, tile->in_link_fseq_obj_id[ j ] ) );
      FD_TEST( tile->in_link_fseq[ j ] );
    }
  }
}


static fd_topo_run_tile_t *
find_run_tile( fd_drv_t * drv, char * name ) {
  for( ulong i=0UL; drv->tiles[ i ]; i++ ) {
    if( 0==strcmp( name, drv->tiles[ i ]->name ) ) return drv->tiles[ i ];
  }
  FD_LOG_ERR(( "tile %s not found", name ));
}

static fd_topo_tile_t *
find_topo_tile( fd_drv_t * drv, char * name ) {
  for( ulong i=0UL; i < drv->config.topo.tile_cnt; i++ ) {
    if( 0==strcmp( name, drv->config.topo.tiles[ i ].name ) ) return &drv->config.topo.tiles[ i ];
  }
  FD_LOG_ERR(( "tile %s not found", name ));
}

static fd_topo_run_tile_t *
tile_topo_to_run( fd_drv_t * drv, fd_topo_tile_t * topo_tile ) {
  return find_run_tile( drv, topo_tile->name );
}

static void
init_tiles( fd_drv_t * drv ) {
  for( ulong i=0UL; i<drv->config.topo.tile_cnt; i++ ) {
    /* TODO Hack fix for shred_topo: move to isolated_shred_topo */
    if( FD_UNLIKELY( 0==strcmp( drv->config.topo.tiles[i].name, "replay" ))) {
      continue;
    }
    fd_topo_tile_t * topo_tile = &drv->config.topo.tiles[ i ];
    fd_topo_run_tile_t * run_tile = tile_topo_to_run( drv, topo_tile );

    // tower doesn't have privileged_init (fd_tower_tile)
    if ( FD_LIKELY(run_tile->privileged_init) ) {
      run_tile->privileged_init(&drv->config.topo, topo_tile);
    }

    if (FD_LIKELY(run_tile->unprivileged_init)  ) {
      run_tile->unprivileged_init( &drv->config.topo, topo_tile );
    }
    fd_metrics_register( topo_tile->metrics ); // TODO check if this is correct in a one thread world
  }

  // create funk database . TODO: do this only if isolated tower is called
 // char const* _page_sz = "gigantic";
 // ulong page_cnt = 1UL;
 // ulong near_cpu = fd_log_cpu_id();
 // ulong txn_max = 32UL;
 // ulong rec_max = 128;
 // ulong wksp_tag = 1234UL;
 // ulong seed = 5678UL;
 // ulong iter_max = 1048576UL;

 // fd_wksp_t* wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "funk_wksp", 0UL );
 // void * shfunk = fd_funk_new( fd_wksp_alloc_laddr(wksp, fd_funk_align(), fd_funk_footprint( txn_max, rec_max ), wksp_tag ), wksp_tag, seed, txn_max, rec_max );
 // fd_funk_t tst_[1];
 // fd_funk_t * tst = fd_funk_join( tst_, shfunk );
 // if( FD_UNLIKELY( !tst ) ) FD_LOG_ERR(( "Unable to create tst" ));
}

void
fd_drv_init( fd_drv_t * drv,
             char* topo_name ) {
  /* fd_config_t is too large to be on the stack, so we use a static
     variable. */
  fd_config_t * config = &drv->config;

  strcpy( config->name, "tile_fuzz_driver" );

  char * identity_path = "/tmp/keypair.json";
  char * vote_account_path = "/tmp/vote_account_path.json";
  create_tmp_file( identity_path, "[71,60,17,94,167,87,207,120,61,120,160,233,173,197,58,217,214,218,153,228,116,222,11,211,184,155,118,23,42,117,197,60,201,89,130,105,44,12,187,216,103,89,109,137,91,248,55,31,16,61,21,117,107,68,142,67,230,247,42,14,74,30,158,201]" );
  
  // TODO: can we keep this same ? @liam
  create_tmp_file( vote_account_path, "[71,60,17,94,167,87,207,120,61,120,160,233,173,197,58,217,214,218,153,228,116,222,11,211,184,155,118,23,42,117,197,60,201,89,130,105,44,12,187,216,103,89,109,137,91,248,55,31,16,61,21,117,107,68,142,67,230,247,42,14,74,30,158,201]" );
  strcpy( config->paths.identity_key, identity_path );
  strcpy(config->paths.vote_account, vote_account_path);
  config->consensus.expected_shred_version = 64475;
  config->net.ingress_buffer_size = 16384;

  if( FD_LIKELY( 0==strcmp( topo_name, "isolated_gossip") ) ) {
    isolated_gossip_topo( config, drv->callbacks );
  } else if( FD_LIKELY( 0==strcmp( topo_name, "isolated_shred" ) ) ) {
    isolated_shred_topo( config, drv->callbacks );
  } else if (FD_LIKELY(0==strcmp( topo_name, "isolated_tower"))) {
    isolated_tower_topo( config, drv->callbacks );
  } else {
    FD_LOG_ERR(( "unknown topology name %s", topo_name ));
  }
  back_wksps( &config->topo, drv->callbacks );
  FD_LOG_NOTICE(( "tile cnt: %lu", config->topo.tile_cnt ));
  init_tiles( drv );
}

FD_FN_UNUSED void
fd_drv_housekeeping( fd_drv_t * drv,
                     char * tile_name,
                     int backpressured ) {
  // TODO precompute name to tile mapping (or pass tile in directly)
  fd_topo_tile_t *     topo_tile = find_topo_tile( drv, tile_name );
  fd_topo_run_tile_t * run_tile  = find_run_tile( drv, tile_name );
  /* We could consider doing this branchless with accessing
     STEM macros by name (requires redef before undef in stem */
  void * ctx = fd_topo_obj_laddr( &drv->config.topo, topo_tile->tile_obj_id );
#ifdef FD_HAS_FUZZ
  if( FD_LIKELY( run_tile->metrics_write ) ) run_tile->during_housekeeping( ctx );
  if( FD_LIKELY( !backpressured ) ) {
    if( FD_LIKELY( run_tile->metrics_write ) ) run_tile->metrics_write( ctx );
  }
#else
  (void)ctx;
  (void)run_tile;
  (void)backpressured;
  FD_LOG_ERR(( "requires compilation with FD_HAS_FUZZ" ));
#endif
}


/* TODO wrong API design for stake_out, and links with multiple
        multiple consumers */
void
fd_drv_send( fd_drv_t * drv,
             char     * from,
             char     * to,
             FD_PARAM_UNUSED ulong      in_idx,
             FD_PARAM_UNUSED ulong      sig,
             uchar    * data,
             ulong      data_sz ) {
  fd_topo_t * topo = &drv->config.topo;
  fd_topo_link_t * link = NULL;

  // TODO this is not quite correct, e.g. for rstart_gossi
  for( ulong i = 0UL; i < topo->link_cnt; i++ ) {
    char *name = topo->links[i].name;

    char *underscore = strchr(name, '_');
    ulong front_len  = (ulong)(underscore - name);
    ulong back_len   = strlen(underscore + 1);

    if( FD_UNLIKELY( strncmp(from, name,           front_len) == 0 &&
                     strncmp(to,   underscore + 1, back_len)  == 0 ) ) {
      link = &topo->links[i];
      break;
    }
  }
  if( FD_UNLIKELY( !link ) ) {
    FD_LOG_ERR(("No suitable link found for from='%s' to='%s'", from, to));
  }
  // TODO hack fix for API design TODO comment
  if( FD_UNLIKELY( 0==strcmp( "out", to ) ) ) {
    to = "shred";
  }
  FD_PARAM_UNUSED fd_topo_run_tile_t * to_run_tile  = find_run_tile( drv, to );
  fd_topo_tile_t *     to_topo_tile = find_topo_tile( drv, to );
  FD_PARAM_UNUSED void * ctx = fd_topo_obj_laddr( &drv->config.topo, to_topo_tile->tile_obj_id );
  ulong fake_seq=0UL;
  ulong fake_cr_avail=0UL;
  FD_PARAM_UNUSED fd_stem_context_t fake_stem = {
    .mcaches=&link->mcache,
    .seqs=&fake_seq,
    .depths=&link->depth,
    .cr_avail=&fake_cr_avail,
    .cr_decrement_amount=0UL
  };
  FD_PARAM_UNUSED int charge_busy_before = 0;
  fd_memcpy( link->dcache, data, data_sz );

  #ifdef FD_HAS_FUZZ
  if( to_run_tile->before_credit ) {
    to_run_tile->before_credit( ctx, &fake_stem, &charge_busy_before );
  }
  if( FD_LIKELY( !charge_busy_before ) ) {
    if( to_run_tile->after_credit ) {
      to_run_tile->after_credit( ctx, &fake_stem, NULL, &charge_busy_before );
    }
  }
  if( to_run_tile->before_frag ) {
    int filter = to_run_tile->before_frag( ctx, in_idx, fake_seq, sig );
    if( FD_UNLIKELY( filter ) ) return;
  }
  if( FD_LIKELY( to_run_tile->during_frag ) ) {
    to_run_tile->during_frag( ctx, in_idx, fake_seq, sig, 4UL, data_sz, 0UL);
  }
  if( FD_LIKELY( to_run_tile->after_frag ) ) {
    to_run_tile->after_frag( ctx, in_idx, fake_seq, sig, data_sz, 0UL, 0UL, &fake_stem );
  }
  #else
    FD_LOG_ERR(( "requires compilation with FD_HAS_FUZZ" ));
  #endif
}
