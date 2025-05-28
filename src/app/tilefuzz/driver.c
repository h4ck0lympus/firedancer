#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "../../disco/topo/fd_topob.h"
#include "../../disco/topo/fd_pod_format.h"
#include "../../disco/metrics/fd_metrics.h"
#include "driver.h"
#include "../../disco/net/fd_net_tile.h" /* fd_topos_net_tiles */

// TODO consider making this more like an FD object with new, join, ...

extern fd_topo_run_tile_t fd_tile_gossip;
extern fd_topo_run_tile_t fd_tile_sign;

FD_FN_CONST ulong
fd_drv_footprint( void ) {
  return sizeof(fd_drv_t);
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
  fd_topob_finish( topo, callbacks );
}

/* Maybe similar to what initialize workspaces does, without
   following it closely */
static void
back_wksps( fd_topo_t * topo, fd_topo_obj_callbacks_t * callbacks[] ) {
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

    obj->wksp_id = obj->id;
    topo->workspaces[ obj->wksp_id ].wksp = aligned_alloc( align, obj->footprint );
    obj->offset = 0UL;
    FD_LOG_NOTICE(( "obj %s %lu %lu %lu %lu", obj->name, obj->wksp_id, obj->footprint, obj->offset, align ));
    FD_LOG_NOTICE(( "wksp pointer %p", (void*)topo->workspaces[ obj->wksp_id ].wksp ));
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


static fd_topo_run_tile_t *
find_run_tile( fd_drv_t * drv, char * name ) {
  for( ulong i=0UL; drv->tiles[ i ]; i++ ) {
    if( 0==strcmp( name, drv->tiles[ i ]->name ) ) return drv->tiles[ i ];
  }
  FD_LOG_ERR(( "tile %s not found", name ));
}

static fd_topo_tile_t *
find_topo_tile( fd_drv_t * drv, char * name ) {
  for( ulong i=0UL; drv->config.topo.tile_cnt; i++ ) {
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
  FD_LOG_NOTICE(( "tile cnt: %lu", drv->config.topo.tile_cnt ));
  for( ulong i=0UL; i<drv->config.topo.tile_cnt; i++ ) {
    FD_LOG_NOTICE(( "tile name: %s", drv->config.topo.tiles[ i ].name ));
    fd_topo_tile_t * topo_tile = &drv->config.topo.tiles[ i ];
    fd_topo_run_tile_t * run_tile = tile_topo_to_run( drv, topo_tile );
    run_tile->privileged_init( &drv->config.topo, topo_tile );
    run_tile->unprivileged_init( &drv->config.topo, topo_tile );
    fd_metrics_register( topo_tile->metrics ); // TODO check if this is correct in a one thread world
  }
}

void
fd_drv_init( fd_drv_t * drv,
             char* topo_name ) {
  FD_LOG_NOTICE(( "fd_drv_init" ));
  /* fd_config_t is too large to be on the stack, so we use a static
     variable. */
  fd_config_t * config = &drv->config;

  strcpy( config->name, "tile_fuzz_driver" );

  char * identity_path = "/tmp/keypair.json";
  create_tmp_file( identity_path, "[71,60,17,94,167,87,207,120,61,120,160,233,173,197,58,217,214,218,153,228,116,222,11,211,184,155,118,23,42,117,197,60,201,89,130,105,44,12,187,216,103,89,109,137,91,248,55,31,16,61,21,117,107,68,142,67,230,247,42,14,74,30,158,201]" );
  strcpy( config->paths.identity_key, identity_path );

  char * isolated_gossip_name = "isolated_gossip";
  if( FD_LIKELY( 0==strcmp( topo_name, isolated_gossip_name ) ) ) {
    isolated_gossip_topo( config, drv->callbacks );
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
  if( FD_LIKELY( run_tile->metrics_write ) ) run_tile->metrics_write( ctx );
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


void
fd_drv_send( fd_drv_t * drv,
             char     * from,
             char     * to,
             ulong      in_idx,
             ulong      sig,
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
  fd_topo_run_tile_t * to_run_tile  = find_run_tile( drv, to );
  fd_topo_tile_t *     to_topo_tile = find_topo_tile( drv, to );
  void * ctx = fd_topo_obj_laddr( &drv->config.topo, to_topo_tile->tile_obj_id );
  ulong fake_seq=0UL;
  ulong fake_cr_avail=0UL;
  fd_stem_context_t fake_stem = {
    .mcaches=&link->mcache,
    .seqs=&fake_seq,
    .depths=&link->depth,
    .cr_avail=&fake_cr_avail,
    .cr_decrement_amount=0UL
  };
  int charge_busy_before = 0;
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
    to_run_tile->during_frag( ctx, in_idx, fake_seq, sig, 0, data_sz, 0UL );
  }
  if( FD_LIKELY( to_run_tile->after_frag ) ) {
    to_run_tile->after_frag( ctx, in_idx, fake_seq, sig, data_sz, 0UL, 0UL, &fake_stem );
  }
  #else
    FD_LOG_ERR(( "requires compilation with FD_HAS_FUZZ" ));
  #endif
}
