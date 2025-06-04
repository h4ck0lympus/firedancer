#include "fd_vm_angr_harness.h"
#include "../../../vm/fd_vm_base.h"

uchar vm_struct_mem[ FD_VM_FOOTPRINT ];

void
fd_vm_exec_single_isolated( ulong reg[ 9UL ], ulong instr ) {
  fd_vm_t * vm = fd_vm_join( fd_vm_new( vm_struct_mem ) );
  /* The production way of initializing the VM is to call fd_vm_init
     here we want to stay minial and only initialize what we need. */
  // initialize vm->reg
  /* 1, 10, 11 intentionally skipped, they are special */
  vm->reg[ 0 ] = reg[ 0 ];
  vm->reg[ 2 ] = reg[ 2 ];
  vm->reg[ 3 ] = reg[ 3 ];
  vm->reg[ 4 ] = reg[ 4 ];
  vm->reg[ 5 ] = reg[ 5 ];
  vm->reg[ 6 ] = reg[ 6 ];
  vm->reg[ 7 ] = reg[ 7 ];
  vm->reg[ 8 ] = reg[ 8 ];
  vm->reg[ 9 ] = reg[ 9 ];
  vm->sbpf_version = 3;
  vm->pc = 0;
  vm->ic = 0;
  vm->cu = 1000; /* consider making dynamic */
  vm->frame_cnt = 0;
  //            opcode  dst      src
  ulong const * text = &instr;
  /* technically UB, to get rid of the const */
  vm->text = text;
  /* let the validator pass */
  vm->text_cnt = 1UL;
  vm->text_sz = 8UL;
  vm->rodata = NULL;
  vm->rodata_sz = 0UL;
  int v = fd_vm_validate( vm );
  if ( !v ) {
    FD_LOG_WARNING(( "VM validation failed with %s", fd_vm_strerror( v ) ));
  }
  int r = fd_vm_exec_notrace( vm );
  if ( !r ) {
    FD_LOG_WARNING(( "VM execution failed with %s", fd_vm_strerror( r ) ));;
  }
  reg[ 0 ] = vm->reg[ 0 ];
  reg[ 2 ] = vm->reg[ 2 ];
  reg[ 3 ] = vm->reg[ 3 ];
  reg[ 4 ] = vm->reg[ 4 ];
  reg[ 5 ] = vm->reg[ 5 ];
  reg[ 6 ] = vm->reg[ 6 ];
  reg[ 7 ] = vm->reg[ 7 ];
  reg[ 8 ] = vm->reg[ 8 ];
  reg[ 9 ] = vm->reg[ 9 ];
}
