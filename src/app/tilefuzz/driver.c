#include "../shared/fd_config.h"
#include "../../disco/topo/fd_topob.h"
#include "../../disco/topo/fd_pod_format.h"
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include "../firedancer/config.h"
#include "../shared/fd_obj_callbacks.h"


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

static void
isolated_gossip_topo( config_t * config ) {
  fd_topo_t * topo = &config->topo;
  fd_topob_new( &config->topo, config->name );
  topo->max_page_size = 4096UL;
  fd_topob_wksp( topo, "metric_in" );
  fd_topob_wksp( topo, "gossip" );
  fd_topo_tile_t * gossip_tile = fd_topob_tile( topo, "gossip", "gossip", "metric_in", 0UL, 0, 0 );

  strncpy( gossip_tile->gossip.identity_key_path, config->consensus.identity_path, sizeof(gossip_tile->gossip.identity_key_path) );
  gossip_tile->gossip.gossip_listen_port     = 0;
  gossip_tile->gossip.ip_addr                = 0u;
  gossip_tile->gossip.expected_shred_version = 50093UL;
  gossip_tile->gossip.entrypoints_cnt = FD_TOPO_GOSSIP_ENTRYPOINTS_MAX;
  FD_STATIC_ASSERT( FD_TOPO_GOSSIP_ENTRYPOINTS_MAX<256UL, "dummy address encoding scheme only works for 8-bit" );
  for( uchar i=0; i<FD_TOPO_GOSSIP_ENTRYPOINTS_MAX; i++ ) {
    gossip_tile->gossip.entrypoints[i].addr = (uint)(i<<24 | i<<16 | i<<8 | i);
    gossip_tile->gossip.entrypoints[i].port = i;
  }

  fd_topob_wksp( topo, "sign" );
  fd_topo_tile_t * sign_tile = fd_topob_tile( topo, "sign", "sign", "metric_in", 0UL, 0, 1 );
  strncpy( sign_tile->sign.identity_key_path, config->consensus.identity_path, sizeof(sign_tile->sign.identity_key_path) );
  fd_topob_wksp( topo, "gossip_sign"  );
  fd_topob_link( topo, "gossip_sign", "gossip_sign", 128UL, 2048UL, 1UL );
  fd_topob_tile_in( topo, "sign", 0UL, "metric_in", "gossip_sign", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  fd_topob_wksp( topo, "sign_gossip"  );
  fd_topob_link( topo, "sign_gossip", "sign_gossip", 128UL,   64UL, 1UL );
  fd_topob_tile_out( topo, "sign", 0UL, "sign_gossip", 0UL );

  fd_topo_obj_t * poh_shred_obj = fd_topob_obj( topo, "fseq", "gossip" );
  FD_TEST( fd_pod_insertf_ulong( topo->props, poh_shred_obj->id, "poh_shred" ) );
  fd_topob_tile_uses( topo, gossip_tile, poh_shred_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topo_obj_callbacks_t * cbs[] = {
      NULL,
  };
  fd_topob_finish( topo, cbs );
}

void
fd_drv_init( char* topo_name ) {
  /* fd_config_t is too large to be on the stack, so we use a static
     variable. */
  static fd_config_t config = { 0 };

  strcpy( config.name, "tile_fuzz_driver" );

  char * consensus_identity_path = "/tmp/keypair.json";
  create_tmp_file( consensus_identity_path, "[71,60,17,94,167,87,207,120,61,120,160,233,173,197,58,217,214,218,153,228,116,222,11,211,184,155,118,23,42,117,197,60,201,89,130,105,44,12,187,216,103,89,109,137,91,248,55,31,16,61,21,117,107,68,142,67,230,247,42,14,74,30,158,201]" );
  strcpy( config.consensus.identity_path, consensus_identity_path );

  char* isolated_gossip_name = "isolated_gossip";
  if( FD_LIKELY( strcmp( topo_name, isolated_gossip_name )==0 ) ) {
    isolated_gossip_topo( &config );
    fd_tile_gossip.privileged_init( &config.topo, &config.topo.tiles[0] );
  }
}
