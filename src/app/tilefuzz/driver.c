#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include "../../disco/topo/fd_topob.h"
#include "../../disco/topo/fd_pod_format.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../firedancer/config.h"
#include "driver.h"

// TODO consider making this more like an FD object with new, join, ...

extern fd_topo_run_tile_t fd_tile_gossip;

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
  fd_topo_tile_t * gossip_tile = fd_topob_tile( topo, "gossip", "gossip", "metric_in", 0UL, 0, 0 );

  strncpy( gossip_tile->gossip.identity_key_path, config->consensus.identity_path, sizeof(gossip_tile->gossip.identity_key_path) );
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
  strncpy( sign_tile->sign.identity_key_path, config->consensus.identity_path, sizeof(sign_tile->sign.identity_key_path) );

  fd_topob_wksp    ( topo, "gossip_sign" );
  fd_topob_link    ( topo, "gossip_sign", "gossip_sign", 128UL, 2048UL, 1UL );
  fd_topob_tile_in ( topo, "sign", 0UL, "metric_in", "gossip_sign", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  fd_topob_wksp    ( topo, "sign_gossip" );
  fd_topob_link    ( topo, "sign_gossip", "sign_gossip", 128UL, 64UL, 1UL );
  fd_topob_tile_out( topo, "sign", 0UL, "sign_gossip", 0UL );
  fd_topob_tile_in ( topo, "gossip", 0UL, "metric_in", "sign_gossip",  0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
  fd_topob_tile_out( topo, "gossip", 0UL, "gossip_sign", 0UL );

  fd_topo_obj_t * poh_shred_obj = fd_topob_obj( topo, "fseq", "gossip" );
  FD_TEST( fd_pod_insertf_ulong( topo->props, poh_shred_obj->id, "poh_shred" ) );
  fd_topob_tile_uses( topo, gossip_tile, poh_shred_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_finish( topo, callbacks );
}

/* Maybe similar to what initialize workspaces does, without
   following it closely */
static void
fd_drv_back_wksps( fd_topo_t * topo, fd_topo_obj_callbacks_t * callbacks[] ) {
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

    FD_LOG_NOTICE(( "obj %s %lu %lu %lu %lu", obj->name, obj->wksp_id, obj->footprint, obj->offset, align ));
    obj->wksp_id = obj->id;
    topo->workspaces[ obj->wksp_id ].wksp = aligned_alloc( align, obj->footprint );
    FD_LOG_NOTICE(( "wksp pointer %p", (void*)topo->workspaces[ obj->wksp_id ].wksp ));
    obj->offset = 0UL;
    /* ~equivalent to fd_topo_wksp_new in a world of real workspaces */
    if( FD_UNLIKELY( cb->new ) ) { /* only saw this null for tiles */
      cb->new( topo, obj );
    }
    // TODO add ASAN and MSAN poisoned memory before and after
  }

  /* The rest of this function an adoption of fd_topo_wksp_fill without
     the wksp id checks.  I haven't looked into why they are needed */
  for( ulong i=0UL; i<topo->link_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ i ];

    link->mcache = fd_mcache_join( fd_topo_obj_laddr( topo, link->mcache_obj_id ) );
    FD_TEST( link->mcache );
    /* only saw this false for tile code */
    if( FD_LIKELY( link->mtu ) ) {
      link->dcache = fd_dcache_join( fd_topo_obj_laddr( topo, link->dcache_obj_id ) );
      FD_TEST( link->dcache );
    }
  }

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];

    tile->metrics = fd_metrics_join( fd_topo_obj_laddr( topo, tile->metrics_obj_id ) );
    FD_TEST( tile->metrics );

    for( ulong j=0UL; j<tile->in_cnt; j++ ) {
      tile->in_link_fseq[ j ] = fd_fseq_join( fd_topo_obj_laddr( topo, tile->in_link_fseq_obj_id[ j ] ) );
      FD_TEST( tile->in_link_fseq[ j ] );
    }
  }
}

fd_config_t *
fd_drv_init( char* topo_name,
             fd_topo_obj_callbacks_t * callbacks[] ) {
  /* fd_config_t is too large to be on the stack, so we use a static
     variable. */
  fd_config_t * config = malloc( sizeof(fd_config_t) );
  if( FD_UNLIKELY( !config ) ) FD_LOG_ERR(( "malloc failed" ));

  strcpy( config->name, "tile_fuzz_driver" );

  char * consensus_identity_path = "/tmp/keypair.json";
  create_tmp_file( consensus_identity_path, "[71,60,17,94,167,87,207,120,61,120,160,233,173,197,58,217,214,218,153,228,116,222,11,211,184,155,118,23,42,117,197,60,201,89,130,105,44,12,187,216,103,89,109,137,91,248,55,31,16,61,21,117,107,68,142,67,230,247,42,14,74,30,158,201]" );
  strcpy( config->consensus.identity_path, consensus_identity_path );

  char* isolated_gossip_name = "isolated_gossip";
  if( FD_LIKELY( strcmp( topo_name, isolated_gossip_name )==0 ) ) {
    isolated_gossip_topo( config,      callbacks );
    fd_drv_back_wksps   ( &config->topo, callbacks );

    fd_tile_gossip.privileged_init  ( &config->topo, config->topo.tiles );
    fd_tile_gossip.unprivileged_init( &config->topo, config->topo.tiles );
  }
  return config;
}

FD_FN_UNUSED void
fd_drv_housekeeping( fd_topo_t * topo, fd_topo_tile_t * tile, fd_topo_run_tile_t ** tiles, int backpressured  ) {
  // TODO precompute name to tile mapping
  fd_topo_run_tile_t * target = NULL;
  for( ulong i=0UL; tiles[ i ]; i++ ) {
    if( 0==strcmp( tile->name, tiles[ i ]->name ) ) target = tiles[ i ];
  }
  /* We could consider to do this branchless with accessing
   * STEM macros by name (requires redef before undef in stem */
  void * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
#ifdef FD_HAS_FUZZ
  if( FD_LIKELY( target->metrics_write ) ) target->metrics_write( ctx );
  if( FD_LIKELY( !backpressured ) ) {
    if( FD_LIKELY( target->metrics_write ) ) target->metrics_write( ctx );
  }
#else
  (void)target;
  (void)ctx;
  (void)backpressured;
  FD_LOG_ERR(( "requires compilation with FD_HAS_FUZZ" ));
#endif
}
