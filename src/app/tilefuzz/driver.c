#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>

#include "../../disco/topo/fd_topob.h"
#include "../../util/pod/fd_pod_format.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/pack/fd_microblock.h"
#include "driver.h"
#include "../../disco/net/fd_net_tile.h" /* fd_topos_net_tiles */
#include "../../flamenco/snapshot/fd_snapshot_loader.h" /* FD_SNAPSHOT_SRC_HTTP */
#include "../shared/commands/run/run.h" /* initialize_workspaces */


#include <sys/random.h>
#include <sys/stat.h> /* mkdir */

// TODO consider making this more like an FD object with new, join, ...

extern fd_topo_run_tile_t fd_tile_gossip;
extern fd_topo_run_tile_t fd_tile_shred;
extern fd_topo_run_tile_t fd_tile_sign;
extern fd_topo_run_tile_t fd_tile_replay;
extern fd_topo_run_tile_t fd_tile_tower;
extern fd_topo_run_tile_t fd_tile_send;

#define FD_HAS_FUZZ 1

FD_FN_CONST ulong
fd_drv_footprint( void ) {
  return sizeof(fd_drv_t);
}

FD_FN_CONST ulong
fd_drv_align( void ) {
  return alignof(fd_drv_t);
}

void *
fd_drv_new( void * shmem, fd_topo_run_tile_t ** tiles, fd_topo_obj_callbacks_t ** callbacks, configure_stage_t ** stages ) {
  fd_drv_t * drv = (fd_drv_t *)shmem;
  drv->tiles = tiles;
  drv->callbacks = callbacks;
  drv->config = (fd_config_t){0};
  drv->stages = stages;
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
mock_funk_txns(fd_drv_t* drv){
  (void)drv;
  fd_funk_t* funk = drv_funk;
  // fd_topo_tile_t * tower_tile = find_topo_tile(drv, "tower");
  // fd_funk_t* funk = fd_topo_obj_laddr(&drv->config.topo, tower_tile->tower.funk_obj_id);

  // parent slot txn
  fd_funk_txn_xid_t parent_xid = {.ul = {1, 1}};  
  fd_funk_txn_start_write(funk);  
  fd_funk_txn_t* parent_txn = fd_funk_txn_prepare(funk, NULL, &parent_xid, 1);  
  fd_funk_txn_end_write(funk);  
    
  if (!parent_txn) {  
    FD_LOG_ERR(("Failed to create parent transaction"));  
    return;  
  }

  for (uint slot=2; slot <= MAX_FUNK_TXNS; slot++) {
    fd_funk_txn_xid_t xid = {.ul = {slot, slot}};
    fd_funk_txn_start_write(funk);
    fd_funk_txn_t* mock_txn = fd_funk_txn_prepare(funk, parent_txn, &xid, 1);
    fd_funk_txn_end_write(funk);

    if (!mock_txn) {
      FD_LOG_WARNING(("Failed to prepare mock txn for slot %u", slot));
    }
  }
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

static void
isolated_tower_topo(config_t* config, fd_topo_obj_callbacks_t* callbacks[])
{
  fd_topo_t * topo = &config->topo;
  fd_topob_new( &config->topo, config->name );

  // create necessary workspaces
  fd_topob_wksp(topo, "metric_in");
  fd_topob_wksp(topo, "gossip");
  fd_topob_wksp(topo, "tower");
  fd_topob_wksp(topo, "gossip_tower");
  fd_topob_wksp(topo, "replay_tower");
  fd_topob_wksp(topo, "stake_out");
 
  // creating links
  fd_topob_link(topo, "gossip_tower", "gossip_tower", 128UL, FD_TPU_MTU, 1UL );
  fd_topob_link(topo, "replay_tower", "replay_tower", 128UL, 65536UL, 1UL );
  fd_topob_link(topo, "tower_replay", "replay_tower", 128UL, 0, 1UL );
  fd_topob_link(topo, "stake_out", "stake_out", 128UL, 40UL + 40200UL * 40UL,  1UL);
  // create tower tile
  fd_topo_tile_t* tower_tile = fd_topob_tile(topo, "tower", "tower", "metric_in", 0, 0, 0);

  // funk setup
  config->firedancer.funk.max_account_records =  10000000;  
  config->firedancer.funk.max_database_transactions = MAX_FUNK_TXNS;  
  config->firedancer.funk.heap_size_gib = 1;

  fd_topob_wksp(topo, "funk");
  FD_PARAM_UNUSED fd_topo_obj_t * funk_obj = setup_topo_funk( topo, "funk",
      config->firedancer.funk.max_account_records,
      config->firedancer.funk.max_database_transactions,
      config->firedancer.funk.heap_size_gib 
    );
  
  // do necessary config required by tower
  tower_tile->tower.funk_obj_id = funk_obj->id;
  strncpy(tower_tile->tower.identity_key_path, config->paths.identity_key, sizeof(tower_tile->tower.identity_key_path));
  strncpy(tower_tile->tower.vote_acc_path, config->paths.vote_account, sizeof(tower_tile->tower.vote_acc_path));
 
  // tower requires initialization of gossip tile and replay tile
  fd_topo_tile_t* gossip_tile = fd_topob_tile(topo, "gossip", "gossip", "metric_in", 0, 0, 0);
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

  fd_topob_wksp(topo, "tower_send");
  fd_topob_link( topo, "tower_send",   "tower_send", 65536UL, sizeof(fd_txn_p_t), 1UL);
  fd_topob_tile_out(topo, "tower", 0UL, "tower_send",0UL);
  fd_topob_tile_in(topo, "tower", 0UL, "metric_in", "replay_tower", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED);
  fd_topob_tile_in(topo, "tower", 0UL, "metric_in", "gossip_tower", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED);
  fd_topob_tile_out(topo, "tower", 0UL, "tower_replay", 0UL);

  fd_topob_wksp( topo, "sign" );
  fd_topo_tile_t * sign_tile = fd_topob_tile( topo, "sign", "sign", "metric_in", 0UL, 0, 1 );
  strncpy( sign_tile->sign.identity_key_path, config->paths.identity_key, sizeof(sign_tile->sign.identity_key_path) );

  // sign is needed for working of gossip
  fd_topob_wksp    ( topo, "gossip_sign" );
  fd_topob_link    ( topo, "gossip_sign", "gossip_sign", 128UL, 2048UL, 1UL );
  fd_topob_tile_in ( topo, "sign", 0UL, "metric_in", "gossip_sign", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  fd_topob_wksp    ( topo, "sign_gossip" );
  fd_topob_link    ( topo, "sign_gossip", "sign_gossip", 128UL, 64UL, 1UL );
  fd_topob_tile_out( topo, "sign", 0UL, "sign_gossip", 0UL );
  fd_topob_tile_in ( topo, "gossip", 0UL, "metric_in", "sign_gossip",  0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
  fd_topob_tile_out( topo, "gossip", 0UL, "gossip_sign", 0UL );
  fd_topob_tile_out( topo, "gossip",   0UL, "gossip_tower", 0UL);

  fd_topo_obj_t * poh_shred_obj = fd_topob_obj( topo, "fseq", "gossip" );
  FD_TEST( fd_pod_insertf_ulong( topo->props, poh_shred_obj->id, "poh_shred" ) );
  fd_topob_tile_uses( topo, gossip_tile, poh_shred_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topob_wksp(topo, "slot_fseqs");
  fd_topo_obj_t* root_slot_obj = fd_topob_obj(topo, "fseq", "slot_fseqs");
  fd_topob_tile_uses(topo, tower_tile, root_slot_obj, FD_SHMEM_JOIN_MODE_READ_WRITE);
  FD_TEST(fd_pod_insertf_ulong(topo->props, root_slot_obj->id, "root_slot"));

  fd_topob_wksp(topo, "shred");
  fd_topo_tile_t* shred_tile = fd_topob_tile(topo, "shred", "shred", "metric_in", 0, 0, 1);
  strncpy( shred_tile->shred.identity_key_path, config->paths.identity_key, sizeof(shred_tile->shred.identity_key_path) );
  shred_tile->shred.depth = 1UL;
  /* We might not need so much for testing, but this is the default.
     If we ever want to save memory, then consider lowering it. */
  config->tiles.shred.max_pending_shred_sets = 16384; // 2^14
  shred_tile->shred.fec_resolver_depth = 16384;
  shred_tile->shred.expected_shred_version = config->consensus.expected_shred_version;
  shred_tile->shred.shred_listen_port = 123;
  shred_tile->shred.larger_shred_limits_per_block = 0;
  shred_tile->shred.adtl_dest.ip = 123;
  shred_tile->shred.adtl_dest.port = 123;
  shred_tile->shred.depth = 65536UL;

  fd_topob_wksp    ( topo, "shred_store" );
  fd_topob_link( topo, "shred_store",  "shred_store",  65536UL, 4UL*FD_SHRED_STORE_MTU, 4UL+config->tiles.shred.max_pending_shred_sets );
  fd_topob_tile_out( topo, "shred", 0UL, "shred_store", 0UL );

  fd_topob_wksp    ( topo, "shred_net" );
  fd_topob_link    ( topo, "shred_net",  "shred_net", 128UL, 2048UL, 1UL );
  fd_topob_tile_out( topo, "shred", 0UL, "shred_net", 0UL );

  fd_topob_wksp    ( topo, "shred_sign" );
  fd_topob_link    ( topo, "shred_sign", "shred_sign", 128UL, 32UL, 1UL );
  fd_topob_tile_in ( topo, "sign", 0UL, "metric_in", "shred_sign", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );

  fd_topob_wksp    ( topo, "sign_shred" );
  fd_topob_link    ( topo, "sign_shred", "sign_shred", 128UL, 64UL, 1UL );
  fd_topob_tile_out( topo, "sign", 0UL, "sign_shred", 0UL );
  fd_topob_tile_in ( topo, "shred", 0UL, "metric_in", "sign_shred",  0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
  fd_topob_tile_out( topo, "shred", 0UL, "shred_sign", 0UL );
  
  fd_topob_finish(topo, callbacks);
  fd_topo_print_log( /* stdout */ 1, topo );
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
  fd_topo_print_log( /* stdout */ 1, topo );
}

static void
isolated_shred_topo( config_t * config, fd_topo_obj_callbacks_t * callbacks[] ) {
  fd_topo_t * topo = &config->topo;
  fd_topob_new( &config->topo, config->name );
  fd_topob_wksp( topo, "metric_in" );
  fd_topob_wksp( topo, "shred" );
  fd_topo_tile_t * shred_tile = fd_topob_tile( topo, "shred", "shred", "metric_in", 0UL, 0, 1 );

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
}

void
fd_drv_init( fd_drv_t * drv,
             char* topo_name ) {
  /* fd_config_t is too large to be on the stack, so we use a static
     variable. */
  fd_config_t * config = &drv->config;

  strcpy( config->name, "tile_fuzz_driver" );

  char * identity_path = "./keypair.json";
  char * vote_account_path = "./vote_account_path.json";
  create_tmp_file( identity_path, "[71,60,17,94,167,87,207,120,61,120,160,233,173,197,58,217,214,218,153,228,116,222,11,211,184,155,118,23,42,117,197,60,201,89,130,105,44,12,187,216,103,89,109,137,91,248,55,31,16,61,21,117,107,68,142,67,230,247,42,14,74,30,158,201]" );
  
  // TODO: can we keep this same ? @liam
  create_tmp_file( vote_account_path, "[71,60,17,94,167,87,207,120,61,120,160,233,173,197,58,217,214,218,153,228,116,222,11,211,184,155,118,23,42,117,197,60,201,89,130,105,44,12,187,216,103,89,109,137,91,248,55,31,16,61,21,117,107,68,142,67,230,247,42,14,74,30,158,201]" );
  strcpy( config->paths.identity_key, identity_path );
  strcpy( config->paths.vote_account, vote_account_path );
  config->consensus.expected_shred_version = 64475;
  config->net.ingress_buffer_size = 16384;

  strcpy( config->hugetlbfs.huge_page_mount_path, "/mnt/.fd/.huge" );
  strcpy( config->hugetlbfs.gigantic_page_mount_path, "/mnt/.fd/.gigantic" );

  /* the umout is most certainly not the best way to do this (check if
     the fd is dynamic with respect to topo/size changes */
  umount( config->hugetlbfs.huge_page_mount_path );
  umount( config->hugetlbfs.gigantic_page_mount_path );

  if( FD_LIKELY( 0==strcmp( topo_name, "isolated_gossip") ) ) {
    isolated_gossip_topo( config, drv->callbacks );
  } else if( FD_LIKELY( 0==strcmp( topo_name, "isolated_shred" ) ) ) {
    isolated_shred_topo( config, drv->callbacks );
  } else if (FD_LIKELY(0==strcmp( topo_name, "isolated_tower"))) {
    isolated_tower_topo( config, drv->callbacks );
  } else {
    FD_LOG_ERR(( "unknown topology name %s", topo_name ));
  }
  // back_wksps( &config->topo, drv->callbacks );
  STAGES[0]->init( config );
  initialize_workspaces( config );
  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topo_fill( &config->topo );


  FD_LOG_NOTICE(( "tile cnt: %lu", config->topo.tile_cnt ));
  init_tiles( drv );

  if (strcmp(topo_name, "isolated_tower") == 0) {
    mock_funk_txns(drv);
  }
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
  for( ulong i = 0UL; i<topo->link_cnt; i++ ) {
    char *name = topo->links[i].name;

    char *underscore = strchr(name, '_');
    ulong front_len  = (ulong)(underscore - name);
    ulong back_len   = strlen(underscore + 1);

    if( FD_UNLIKELY( strncmp(from, name,           front_len) == 0 &&
                     strncmp(to,   underscore + 1, back_len)  == 0 ) ) {
      link = &topo->links[i];
      FD_LOG_NOTICE(("link %s: %p", name, (void*)link));
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
  // FD_LOG_NOTICE(("ctx in driver.c: %p", ctx));
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
  FD_LOG_NOTICE(("link->dcache: %p", link->dcache));

  // rather than statically send 4UL as chunk idx calculate correct chunk idx
  void * base = fd_wksp_containing( link->dcache );
  ulong chunk = fd_dcache_compact_chunk0( base, link->dcache );
  FD_PARAM_UNUSED uchar * volatile dst = (uchar *)fd_chunk_to_laddr( base, chunk );

  #ifdef FD_HAS_FUZZ
  link->mcache->hook = fd_drv_publish_hook;
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
    to_run_tile->during_frag( ctx, in_idx, fake_seq, sig, chunk, data_sz, 0UL);
  }
  if( FD_LIKELY( to_run_tile->after_frag ) ) {
    to_run_tile->after_frag( ctx, in_idx, fake_seq, sig, data_sz, 0UL, 0UL, &fake_stem );
  }
  #else
    FD_LOG_ERR(( "requires compilation with FD_HAS_FUZZ" ));
  #endif
}
