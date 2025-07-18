#include "fd_vm_syscall.h"
#include "../../runtime/program/fd_vote_program.h"
#include "../../runtime/sysvar/fd_sysvar.h"
#include "../../runtime/sysvar/fd_sysvar_clock.h"
#include "../../runtime/sysvar/fd_sysvar_epoch_rewards.h"
#include "../../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../runtime/sysvar/fd_sysvar_rent.h"
#include "../../runtime/sysvar/fd_sysvar_last_restart_slot.h"
#include "../../runtime/context/fd_exec_txn_ctx.h"
#include "../../runtime/context/fd_exec_instr_ctx.h"
#include "../../runtime/fd_system_ids.h"

int
fd_vm_syscall_sol_get_clock_sysvar( /**/            void *  _vm,
                                    /**/            ulong   out_vaddr,
                                    FD_PARAM_UNUSED ulong   r2,
                                    FD_PARAM_UNUSED ulong   r3,
                                    FD_PARAM_UNUSED ulong   r4,
                                    FD_PARAM_UNUSED ulong   r5,
                                    /**/            ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* FIXME: In the original version of this code, there was an FD_TEST
     to check if the VM was attached to an instruction context (that
     would have crashed anyway because of pointer chasing).  If the VM
     is being run outside the Solana runtime, it should never invoke
     this syscall in the first place.  So we treat this as a SIGCALL in
     a non-crashing way. */

  fd_exec_instr_ctx_t const * instr_ctx = vm->instr_ctx;
  if( FD_UNLIKELY( !instr_ctx ) ) return FD_VM_SYSCALL_ERR_OUTSIDE_RUNTIME;

  FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( FD_VM_SYSVAR_BASE_COST, sizeof(fd_sol_sysvar_clock_t) ) );

  void * out = FD_VM_MEM_HADDR_ST( vm, out_vaddr, FD_VM_ALIGN_RUST_SYSVAR_CLOCK, sizeof(fd_sol_sysvar_clock_t) );


  fd_sol_sysvar_clock_t const * clock = fd_sysvar_clock_read( instr_ctx->txn_ctx->funk,
                                                              instr_ctx->txn_ctx->funk_txn,
                                                              instr_ctx->txn_ctx->spad );
  if( FD_UNLIKELY( !clock ) ) {
    FD_LOG_ERR(( "failed to read sysvar clock" ));
  }

  memcpy( out, clock, sizeof(fd_sol_sysvar_clock_t) );

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_get_epoch_schedule_sysvar( /**/            void *  _vm,
                                             /**/            ulong   out_vaddr,
                                             FD_PARAM_UNUSED ulong   r2,
                                             FD_PARAM_UNUSED ulong   r3,
                                             FD_PARAM_UNUSED ulong   r4,
                                             FD_PARAM_UNUSED ulong   r5,
                                             /**/            ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* FIXME: In the original version of this code, there was an FD_TEST
     to check if the VM was attached to an instruction context (that
     would have crashed anyway because of pointer chasing).  If the VM
     is being run outside the Solana runtime, it should never invoke
     this syscall in the first place.  So we treat this as a SIGCALL in
     a non-crashing way for the time being. */

  fd_exec_instr_ctx_t const * instr_ctx = vm->instr_ctx;
  if( FD_UNLIKELY( !instr_ctx ) ) return FD_VM_SYSCALL_ERR_OUTSIDE_RUNTIME;

  FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( FD_VM_SYSVAR_BASE_COST, sizeof(fd_epoch_schedule_t) ) );

  void * out = FD_VM_MEM_HADDR_ST( vm, out_vaddr, FD_VM_ALIGN_RUST_SYSVAR_EPOCH_SCHEDULE, sizeof(fd_epoch_schedule_t) );

  fd_epoch_schedule_t * schedule = fd_sysvar_epoch_schedule_read( instr_ctx->txn_ctx->funk,
                                                                  instr_ctx->txn_ctx->funk_txn,
                                                                  instr_ctx->txn_ctx->spad );
  if( FD_UNLIKELY( schedule == NULL ) ) {
    FD_LOG_ERR(( "failed to read sysvar epoch schedule" ));
  }

  memcpy( out, schedule, sizeof(fd_epoch_schedule_t) );

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_get_rent_sysvar( /**/            void *  _vm,
                                   /**/            ulong   out_vaddr,
                                   FD_PARAM_UNUSED ulong   r2,
                                   FD_PARAM_UNUSED ulong   r3,
                                   FD_PARAM_UNUSED ulong   r4,
                                   FD_PARAM_UNUSED ulong   r5,
                                   /**/            ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* FIXME: In the original version of this code, there was an FD_TEST
     to check if the VM was attached to an instruction context (that
     would have crashed anyway because of pointer chasing).  If the VM
     is being run outside the Solana runtime, it should never invoke
     this syscall in the first place.  So we treat this as a SIGCALL in
     a non-crashing way for the time being. */

  fd_exec_instr_ctx_t const * instr_ctx = vm->instr_ctx;
  if( FD_UNLIKELY( !instr_ctx ) ) return FD_VM_SYSCALL_ERR_OUTSIDE_RUNTIME;

  FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( FD_VM_SYSVAR_BASE_COST, sizeof(fd_rent_t) ) );

  void * out = FD_VM_MEM_HADDR_ST( vm, out_vaddr, FD_VM_ALIGN_RUST_SYSVAR_RENT, sizeof(fd_rent_t) );

  fd_rent_t const * rent = fd_sysvar_rent_read( instr_ctx->txn_ctx->funk,
                                                instr_ctx->txn_ctx->funk_txn,
                                                instr_ctx->txn_ctx->spad );
  if( FD_UNLIKELY( !rent ) ) {
    FD_LOG_ERR(( "failed to read sysvar rent" ));
  }

  memcpy( out, rent, sizeof(fd_rent_t) );

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/36323b6dcd3e29e4d6fe6d73d716a3f33927148b/programs/bpf_loader/src/syscalls/sysvar.rs#L144 */
int
fd_vm_syscall_sol_get_last_restart_slot_sysvar( /**/            void *  _vm,
                                                /**/            ulong   out_vaddr,
                                                FD_PARAM_UNUSED ulong   r2,
                                                FD_PARAM_UNUSED ulong   r3,
                                                FD_PARAM_UNUSED ulong   r4,
                                                FD_PARAM_UNUSED ulong   r5,
                                                /**/            ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( FD_VM_SYSVAR_BASE_COST, sizeof(fd_sol_sysvar_last_restart_slot_t) ) );

  fd_sol_sysvar_last_restart_slot_t * out = FD_VM_MEM_HADDR_ST( vm,
                                                                out_vaddr,
                                                                FD_VM_ALIGN_RUST_SYSVAR_LAST_RESTART_SLOT,
                                                                sizeof(fd_sol_sysvar_last_restart_slot_t) );

  fd_sol_sysvar_last_restart_slot_t * last_restart_slot = fd_sysvar_last_restart_slot_read( vm->instr_ctx->txn_ctx->funk,
                                                                                            vm->instr_ctx->txn_ctx->funk_txn,
                                                                                            vm->instr_ctx->txn_ctx->spad );
  if( FD_UNLIKELY( !last_restart_slot ) ) {
    FD_LOG_ERR(( "failed to read sysvar last restart slot" ));
  }
  *out = *last_restart_slot;

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/sysvar.rs#L167-L232 */
int
fd_vm_syscall_sol_get_sysvar( /**/            void *  _vm,
                              /**/            ulong   sysvar_id_vaddr,
                              /**/            ulong   out_vaddr,
                              /**/            ulong   offset,
                              /**/            ulong   sz,
                              FD_PARAM_UNUSED ulong   r5,
                              /**/            ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* sysvar_id_cost seems to just always be 32 / 250 = 0...
     https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/sysvar.rs#L190-L197 */
  ulong sysvar_buf_cost = sz / FD_VM_CPI_BYTES_PER_UNIT;
  FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( FD_VM_SYSVAR_BASE_COST, fd_ulong_max( sysvar_buf_cost, FD_VM_MEM_OP_BASE_COST ) ) );

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/sysvar.rs#L199-L200 */
  const fd_pubkey_t * sysvar_id = FD_VM_MEM_HADDR_LD( vm, sysvar_id_vaddr, FD_VM_ALIGN_RUST_PUBKEY, FD_PUBKEY_FOOTPRINT );

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/sysvar.rs#L202-L203 */
  void * out_haddr = FD_VM_MEM_SLICE_HADDR_ST( vm, out_vaddr, FD_VM_ALIGN_RUST_U8, sz );

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/sysvar.rs#L205-L208 */
  ulong offset_length;
  int err = fd_int_if( __builtin_uaddl_overflow( offset, sz, &offset_length ), FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW, FD_EXECUTOR_INSTR_SUCCESS );
  if( FD_UNLIKELY( err ) ) {
    FD_VM_ERR_FOR_LOG_INSTR( vm, err );
    return FD_VM_SYSCALL_ERR_ABORT;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/sysvar.rs#L210-L213
     We don't need this, we already checked we can store in out_vaddr with requested sz. */

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/sysvar.rs#L215-L221 */
  if( FD_UNLIKELY( memcmp( sysvar_id->uc, fd_sysvar_clock_id.uc,             FD_PUBKEY_FOOTPRINT ) &&
                   memcmp( sysvar_id->uc, fd_sysvar_epoch_schedule_id.uc,    FD_PUBKEY_FOOTPRINT ) &&
                   memcmp( sysvar_id->uc, fd_sysvar_epoch_rewards_id.uc,     FD_PUBKEY_FOOTPRINT ) &&
                   memcmp( sysvar_id->uc, fd_sysvar_rent_id.uc,              FD_PUBKEY_FOOTPRINT ) &&
                   memcmp( sysvar_id->uc, fd_sysvar_slot_hashes_id.uc,       FD_PUBKEY_FOOTPRINT ) &&
                   memcmp( sysvar_id->uc, fd_sysvar_stake_history_id.uc,     FD_PUBKEY_FOOTPRINT ) &&
                   memcmp( sysvar_id->uc, fd_sysvar_last_restart_slot_id.uc, FD_PUBKEY_FOOTPRINT ) ) ) {
    *_ret = 2UL;
    return FD_VM_SUCCESS;
  }

  /* we know that the account data won't be changed for the lifetime of this view, because sysvars don't change inter-block */
  FD_TXN_ACCOUNT_DECL( sysvar_account );
  err = fd_txn_account_init_from_funk_readonly( sysvar_account, sysvar_id, vm->instr_ctx->txn_ctx->funk, vm->instr_ctx->txn_ctx->funk_txn );
  if( FD_UNLIKELY( err ) ) {
    *_ret = 2UL;
    return FD_VM_SUCCESS;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/sysvar.rs#L223-L228
     Note the length check is at the very end to fail after performing sufficient checks. */
  const uchar * sysvar_buf     = sysvar_account->vt->get_data( sysvar_account );
  ulong         sysvar_buf_len = sysvar_account->vt->get_data_len( sysvar_account );

  if( FD_UNLIKELY( offset_length>sysvar_buf_len ) ) {
    *_ret = 1UL;
    return FD_VM_SUCCESS;
  }

  if( FD_UNLIKELY( sz==0UL ) ) {
    *_ret = 0UL;
    return FD_VM_SUCCESS;
  }

  fd_memcpy( out_haddr, sysvar_buf + offset, sz );
  *_ret = 0;
  return FD_VM_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/mod.rs#L2043-L2118

   This syscall is meant to return the latest frozen stakes at an epoch
   boundary.  So for instance, when we are executing in epoch 7, this
   should return the stakes at the end of epoch 6.  Note that this is
   also the stakes that determined the leader schedule for the upcoming
   epoch, namely epoch 8. */
int
fd_vm_syscall_sol_get_epoch_stake( /**/            void *  _vm,
                                   /**/            ulong   var_addr,
                                   FD_PARAM_UNUSED ulong   r2,
                                   FD_PARAM_UNUSED ulong   r3,
                                   FD_PARAM_UNUSED ulong   r4,
                                   FD_PARAM_UNUSED ulong   r5,
                                   /**/            ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* Var addr of 0 returns the total active stake on the cluster.

     https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/mod.rs#L2057-L2075 */
  if( FD_UNLIKELY( var_addr==0UL ) ) {
    /* https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/mod.rs#L2065-L2066 */
    FD_VM_CU_UPDATE( vm, FD_VM_SYSCALL_BASE_COST );

    /* https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/mod.rs#L2074 */
    *_ret = fd_bank_total_epoch_stake_get( vm->instr_ctx->txn_ctx->bank );
    return FD_VM_SUCCESS;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/mod.rs#L2083-L2091 */
  FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( FD_VM_MEM_OP_BASE_COST,
                       fd_ulong_sat_add( FD_VM_SYSCALL_BASE_COST, FD_PUBKEY_FOOTPRINT / FD_VM_CPI_BYTES_PER_UNIT ) ) );

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/mod.rs#L2103-L2104 */
  const fd_pubkey_t * vote_address = FD_VM_MEM_HADDR_LD( vm, var_addr, FD_VM_ALIGN_RUST_PUBKEY, FD_PUBKEY_FOOTPRINT );

  /* https://github.com/anza-xyz/agave/blob/v2.2.14/runtime/src/bank.rs#L6954 */
  fd_vote_accounts_global_t const * next_epoch_stakes = fd_bank_next_epoch_stakes_locking_query( vm->instr_ctx->txn_ctx->bank );
  *_ret = fd_query_pubkey_stake( vote_address, next_epoch_stakes );
  fd_bank_next_epoch_stakes_end_locking_query( vm->instr_ctx->txn_ctx->bank );

  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_get_stack_height( /**/            void *  _vm,
                                    FD_PARAM_UNUSED ulong   r1,
                                    FD_PARAM_UNUSED ulong   r2,
                                    FD_PARAM_UNUSED ulong   r3,
                                    FD_PARAM_UNUSED ulong   r4,
                                    FD_PARAM_UNUSED ulong   r5,
                                    /**/            ulong * _ret ) {
  /* https://github.com/anza-xyz/agave/blob/v2.0.8/programs/bpf_loader/src/syscalls/mod.rs#L1547 */
  fd_vm_t * vm = (fd_vm_t *)_vm;

  FD_VM_CU_UPDATE( vm, FD_VM_SYSCALL_BASE_COST );

  *_ret = vm->instr_ctx->txn_ctx->instr_stack_sz;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_get_return_data( /**/            void *  _vm,
                                   /**/            ulong   dst_vaddr,
                                   /**/            ulong   dst_max,
                                   /**/            ulong   program_id_vaddr,
                                   FD_PARAM_UNUSED ulong   r4,
                                   FD_PARAM_UNUSED ulong   r5,
                                   /**/            ulong * _ret ) {
  /* https://github.com/anza-xyz/agave/blob/v2.0.8/programs/bpf_loader/src/syscalls/mod.rs#L1345 */
  fd_vm_t * vm = (fd_vm_t *)_vm;

  FD_VM_CU_UPDATE( vm, FD_VM_SYSCALL_BASE_COST );

  /* FIXME: In the original version of this code, there was an FD_TEST
     to check if the VM was attached to an instruction context (that
     would have crashed anyway because of pointer chasing).  If the VM
     is being run outside the Solana runtime, it should never invoke
     this syscall in the first place.  So we treat this as a SIGCALL in
     a non-crashing way for the time being. */
  fd_exec_instr_ctx_t const * instr_ctx = vm->instr_ctx;
  if( FD_UNLIKELY( !instr_ctx ) ) return FD_VM_SYSCALL_ERR_OUTSIDE_RUNTIME;

  fd_txn_return_data_t const * return_data    = &instr_ctx->txn_ctx->return_data;
  ulong                        return_data_sz = return_data->len;

  ulong cpy_sz = fd_ulong_min( return_data_sz, dst_max );

  if( FD_LIKELY( cpy_sz ) ) {

    FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( cpy_sz, sizeof(fd_pubkey_t) ) / FD_VM_CPI_BYTES_PER_UNIT );

    void * dst        = FD_VM_MEM_SLICE_HADDR_ST( vm, dst_vaddr, FD_VM_ALIGN_RUST_U8, cpy_sz );

    memcpy( dst,         return_data->data,       cpy_sz              );

    /* https://github.com/anza-xyz/agave/blob/v2.0.8/programs/bpf_loader/src/syscalls/mod.rs#L1376-L1381
       These can never happen. */

    void * program_id = FD_VM_MEM_HADDR_ST( vm, program_id_vaddr, FD_VM_ALIGN_RUST_PUBKEY, sizeof(fd_pubkey_t) );

    FD_VM_MEM_CHECK_NON_OVERLAPPING( vm, (ulong)dst, cpy_sz, (ulong)program_id, sizeof(fd_pubkey_t) );

    memcpy( program_id, &return_data->program_id, sizeof(fd_pubkey_t) );
  }

  *_ret = return_data_sz;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_set_return_data( /**/            void *  _vm,
                                   /**/            ulong   src_vaddr,
                                   /**/            ulong   src_sz,
                                   FD_PARAM_UNUSED ulong   r3,
                                   FD_PARAM_UNUSED ulong   r4,
                                   FD_PARAM_UNUSED ulong   r5,
                                   /**/            ulong * _ret ) {
  /* https://github.com/anza-xyz/agave/blob/v2.0.8/programs/bpf_loader/src/syscalls/mod.rs#L1297 */
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* FIXME: In the original version of this code, there was an FD_TEST
     to check if the VM was attached to an instruction context (that
     would have crashed anyway because of pointer chasing).  If the VM
     is being run outside the Solana runtime, it should never invoke
     this syscall in the first place.  So we treat this as a SIGCALL in
     a non-crashing way for the time being. */
  fd_exec_instr_ctx_t const * instr_ctx = vm->instr_ctx;
  if( FD_UNLIKELY( !instr_ctx ) ) return FD_VM_SYSCALL_ERR_OUTSIDE_RUNTIME;

  FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( FD_VM_SYSCALL_BASE_COST, src_sz / FD_VM_CPI_BYTES_PER_UNIT ) );

  /* https://github.com/anza-xyz/agave/blob/v2.0.8/programs/bpf_loader/src/syscalls/mod.rs#L1316 */
  if( FD_UNLIKELY( src_sz>FD_VM_RETURN_DATA_MAX ) ) {
    /* TODO: this is a bit annoying, we may want to unify return codes...
       - FD_VM_SYSCALL_ERR_RETURN_DATA_TOO_LARGE is Agave's return code,
         also used for logging */
    FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_RETURN_DATA_TOO_LARGE );
    return FD_VM_SYSCALL_ERR_RETURN_DATA_TOO_LARGE;
  }

  /* src_sz == 0 is ok */
  void const * src = FD_VM_MEM_SLICE_HADDR_LD( vm, src_vaddr, FD_VM_ALIGN_RUST_U8, src_sz );

  /* https://github.com/anza-xyz/agave/blob/v2.2.0/programs/bpf_loader/src/syscalls/mod.rs#L1480-L1484 */
  fd_pubkey_t const * program_id = NULL;
  int err = fd_exec_instr_ctx_get_last_program_key( vm->instr_ctx, &program_id );
  if( FD_UNLIKELY( err ) ) {
    FD_VM_ERR_FOR_LOG_INSTR( vm, err );
    return err;
  }

  fd_txn_return_data_t * return_data = &instr_ctx->txn_ctx->return_data;

  return_data->len = src_sz;
  if( FD_LIKELY( src_sz!=0UL ) ) {
    fd_memcpy( return_data->data, src, src_sz );
  }
  return_data->program_id = *program_id;

  *_ret = 0;
  return FD_VM_SUCCESS;
}

/* Used to query and convey information about the sibling instruction
   https://github.com/anza-xyz/agave/blob/70089cce5119c9afaeb2986e2ecaa6d4505ec15d/sdk/program/src/instruction.rs#L676

    */
struct fd_vm_syscall_processed_sibling_instruction {
  /* Length of the instruction data */
  ulong data_len;
  /* Number of accounts */
  ulong accounts_len;
};
typedef struct fd_vm_syscall_processed_sibling_instruction fd_vm_syscall_processed_sibling_instruction_t;

#define FD_VM_SYSCALL_PROCESSED_SIBLING_INSTRUCTION_SIZE  (16UL)
#define FD_VM_SYSCALL_PROCESSED_SIBLING_INSTRUCTION_ALIGN (8UL )

/*
sol_get_last_processed_sibling_instruction returns the last element from a reverse-ordered
list of successfully processed sibling instructions: the "processed sibling instruction list".

For example, given the call flow:
A
B -> C -> D
B
B -> F          (current execution point)

B's processed sibling instruction list is [A]
F's processed sibling instruction list is [E, C]

This allows the current instruction to know what the last processed sibling instruction was.
This is useful to check that critical preceeding instructions have actually executed: for example
ensuring that an assert instruction has successfully executed.

Parameters:
- index:
- result_meta_vaddr: virtual address of the object where metadata about the last processed sibling instruction will be stored upon successful execution (the length of the arrays in the result).
  Has the type solana_program::instruction::ProcessedSiblingInstruction
    https://github.com/anza-xyz/agave/blob/70089cce5119c9afaeb2986e2ecaa6d4505ec15d/sdk/program/src/instruction.rs#L672-L681
- result_program_id_vaddr: virtual address where the pubkey of the program ID of the last processed sibling instruction will be stored upon successful execution
- result_data_vaddr: virtual address where the instruction data of the last processed sibling instruction will be stored upon successful execution. The length of the data will be stored in ProcessedSiblingInstruction.data_len
- result_accounts_vaddr: virtual address where an array of account meta structures will be stored into upon successful execution. The length of the data will be stored in ProcessedSiblingInstruction.accounts_len
  Each account meta has the type solana_program::instruction::AccountMeta
    https://github.com/anza-xyz/agave/blob/70089cce5119c9afaeb2986e2ecaa6d4505ec15d/sdk/program/src/instruction.rs#L525-L548

Result:
If a processed sibling instruction is found then 1 will be written into r0, and the result_* data structures
above will be populated with the last processed sibling instruction.
If there is no processed sibling instruction, 0 will be written into r0.

Syscall entrypoint: https://github.com/anza-xyz/agave/blob/70089cce5119c9afaeb2986e2ecaa6d4505ec15d/programs/bpf_loader/src/syscalls/mod.rs#L1402
*/
int
fd_vm_syscall_sol_get_processed_sibling_instruction(
    void * _vm,
    ulong index,
    ulong result_meta_vaddr,
    ulong result_program_id_vaddr,
    ulong result_data_vaddr,
    ulong result_accounts_vaddr,
    ulong * ret
) {

  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* Consume base compute cost
     https://github.com/anza-xyz/agave/blob/70089cce5119c9afaeb2986e2ecaa6d4505ec15d/programs/bpf_loader/src/syscalls/mod.rs#L1414 */
  FD_VM_CU_UPDATE( vm, FD_VM_SYSCALL_BASE_COST );

  /*
    Get the current instruction stack height.

    Top-level instructions in Agave's invocation stack have a depth of 1
    https://github.com/anza-xyz/agave/blob/d87e23d8d91c32d5f2be2bb3557c730bee1e9434/sdk/program/src/instruction.rs#L732-L733
    Ours have a depth of 0, so we need to add 1 to account for the difference
   */
  ulong stack_height = fd_ulong_sat_add( vm->instr_ctx->depth, 1UL );

  /* Reverse iterate through the instruction trace, ignoring anything except instructions on the same level.
  https://github.com/anza-xyz/agave/blob/70089cce5119c9afaeb2986e2ecaa6d4505ec15d/programs/bpf_loader/src/syscalls/mod.rs#L1422 */
  ulong instruction_trace_length = vm->instr_ctx->txn_ctx->instr_trace_length;
  ulong reverse_index_at_stack_height = 0UL;
  fd_exec_instr_trace_entry_t * trace_entry = NULL;
  for( ulong index_in_trace = instruction_trace_length; index_in_trace > 0UL; index_in_trace-- ) {

    /* https://github.com/anza-xyz/agave/blob/v2.0.8/programs/bpf_loader/src/syscalls/mod.rs#L1432-L1434
       This error can never happen */

    fd_exec_instr_trace_entry_t * candidate_trace_entry = &vm->instr_ctx->txn_ctx->instr_trace[ index_in_trace - 1UL ];
    if( FD_LIKELY( candidate_trace_entry->stack_height < stack_height ) ) {
      break;
    }

    if( FD_UNLIKELY( candidate_trace_entry->stack_height == stack_height ) ) {
      if( FD_UNLIKELY( fd_ulong_sat_add( index, 1UL ) == reverse_index_at_stack_height ) ) {
        trace_entry = candidate_trace_entry;
        break;
      }
      reverse_index_at_stack_height = fd_ulong_sat_add( reverse_index_at_stack_height, 1UL );
    }
  }

  /* If we have found an entry, then copy the instruction into the result addresses
     https://github.com/anza-xyz/agave/blob/70089cce5119c9afaeb2986e2ecaa6d4505ec15d/programs/bpf_loader/src/syscalls/mod.rs#L1440-L1533
   */
  if( FD_LIKELY( trace_entry != NULL ) ) {
    fd_instr_info_t * instr_info = trace_entry->instr_info;

    fd_vm_syscall_processed_sibling_instruction_t * result_meta_haddr = FD_VM_MEM_HADDR_ST(
      vm,
      result_meta_vaddr,
      FD_VM_SYSCALL_PROCESSED_SIBLING_INSTRUCTION_ALIGN,
      FD_VM_SYSCALL_PROCESSED_SIBLING_INSTRUCTION_SIZE );

    /* https://github.com/anza-xyz/agave/blob/70089cce5119c9afaeb2986e2ecaa6d4505ec15d/programs/bpf_loader/src/syscalls/mod.rs#L1447 */
    if( ( result_meta_haddr->data_len == trace_entry->instr_info->data_sz ) &&
        ( result_meta_haddr->accounts_len == trace_entry->instr_info->acct_cnt ) ) {

      fd_pubkey_t * result_program_id_haddr = FD_VM_MEM_HADDR_ST(
        vm,
        result_program_id_vaddr,
        FD_VM_ALIGN_RUST_PUBKEY,
        sizeof(fd_pubkey_t) );

      uchar * result_data_haddr = FD_VM_MEM_SLICE_HADDR_ST(
        vm,
        result_data_vaddr,
        FD_VM_ALIGN_RUST_U8,
        result_meta_haddr->data_len);

      ulong accounts_meta_total_size = fd_ulong_sat_mul( result_meta_haddr->accounts_len, FD_VM_RUST_ACCOUNT_META_SIZE );
      fd_vm_rust_account_meta_t * result_accounts_haddr = FD_VM_MEM_SLICE_HADDR_ST(
        vm,
        result_accounts_vaddr,
        FD_VM_RUST_ACCOUNT_META_ALIGN,
        accounts_meta_total_size);

      /* Check for memory overlaps
         https://github.com/anza-xyz/agave/blob/70089cce5119c9afaeb2986e2ecaa6d4505ec15d/programs/bpf_loader/src/syscalls/mod.rs#L1469 */

      FD_VM_MEM_CHECK_NON_OVERLAPPING( vm,
        (ulong)result_meta_haddr, FD_VM_SYSCALL_PROCESSED_SIBLING_INSTRUCTION_SIZE,
        (ulong)result_program_id_haddr, sizeof(fd_pubkey_t) );
      FD_VM_MEM_CHECK_NON_OVERLAPPING( vm,
        (ulong)result_meta_haddr, FD_VM_SYSCALL_PROCESSED_SIBLING_INSTRUCTION_SIZE,
        (ulong)result_accounts_haddr, accounts_meta_total_size );
      FD_VM_MEM_CHECK_NON_OVERLAPPING( vm,
        (ulong)result_meta_haddr, FD_VM_SYSCALL_PROCESSED_SIBLING_INSTRUCTION_SIZE,
        (ulong)result_data_haddr, result_meta_haddr->data_len );
      FD_VM_MEM_CHECK_NON_OVERLAPPING( vm,
        (ulong)result_program_id_haddr, sizeof(fd_pubkey_t),
        (ulong)result_data_haddr, result_meta_haddr->data_len );
      FD_VM_MEM_CHECK_NON_OVERLAPPING( vm,
        (ulong)result_program_id_haddr, sizeof(fd_pubkey_t),
        (ulong)result_accounts_haddr, accounts_meta_total_size );
      FD_VM_MEM_CHECK_NON_OVERLAPPING( vm,
        (ulong)result_data_haddr, result_meta_haddr->data_len,
        (ulong)result_accounts_haddr, accounts_meta_total_size );

      /* Copy the instruction into the result addresses
         https://github.com/anza-xyz/agave/blob/70089cce5119c9afaeb2986e2ecaa6d4505ec15d/programs/bpf_loader/src/syscalls/mod.rs#L1506-L1528

         Note: we assume that the instr accounts are already correct at this point.
         Agave has many error checks. */

      /* Get the instruction info's program id pubkey. Note we have to use the transaction context's
         get_key_of_account_at_index function the program_id is a transaction-wide account index.
         https://github.com/anza-xyz/agave/blob/v2.2.0/programs/bpf_loader/src/syscalls/mod.rs#L1662-L1663 */
      fd_pubkey_t const * isntr_info_program_id_key = NULL;
      int err = fd_exec_txn_ctx_get_key_of_account_at_index( vm->instr_ctx->txn_ctx,
                                                             instr_info->program_id,
                                                             &isntr_info_program_id_key );
      if( FD_UNLIKELY( err ) ) {
        FD_VM_ERR_FOR_LOG_INSTR( vm, err );
        return err;
      }

      fd_memcpy( result_program_id_haddr->key, isntr_info_program_id_key->key, FD_PUBKEY_FOOTPRINT );
      fd_memcpy( result_data_haddr, instr_info->data, instr_info->data_sz );
      for( ulong i = 0UL; i < instr_info->acct_cnt; i++ ) {
        fd_memcpy( result_accounts_haddr[ i ].pubkey,
                   vm->instr_ctx->txn_ctx->account_keys[ instr_info->accounts[ i ].index_in_transaction ].key,
                   FD_PUBKEY_FOOTPRINT );
        result_accounts_haddr[ i ].is_signer   = !!(instr_info->accounts[ i ].is_signer );
        result_accounts_haddr[ i ].is_writable = !!(instr_info->accounts[ i ].is_writable );
      }
    }

    /* Copy the actual metadata into the result meta struct
       https://github.com/anza-xyz/agave/blob/70089cce5119c9afaeb2986e2ecaa6d4505ec15d/programs/bpf_loader/src/syscalls/mod.rs#L1529-L1531 */
    result_meta_haddr->data_len     = instr_info->data_sz;
    result_meta_haddr->accounts_len = instr_info->acct_cnt;

    /* Return true as we found a sibling instruction
       https://github.com/anza-xyz/agave/blob/70089cce5119c9afaeb2986e2ecaa6d4505ec15d/programs/bpf_loader/src/syscalls/mod.rs#L1532 */
    *ret = 1UL;
    return FD_VM_SUCCESS;
  }

  /* Return false if we didn't find a sibling instruction
     https://github.com/anza-xyz/agave/blob/70089cce5119c9afaeb2986e2ecaa6d4505ec15d/programs/bpf_loader/src/syscalls/mod.rs#L1534 */
  *ret = 0UL;
  return FD_VM_SUCCESS;
}

// https://github.com/anza-xyz/agave/blob/master/programs/bpf_loader/src/syscalls/sysvar.rs#L75
int
fd_vm_syscall_sol_get_epoch_rewards_sysvar( /**/            void *  _vm,
                                            /**/            ulong   out_vaddr,
                                            FD_PARAM_UNUSED ulong   r2,
                                            FD_PARAM_UNUSED ulong   r3,
                                            FD_PARAM_UNUSED ulong   r4,
                                            FD_PARAM_UNUSED ulong   r5,
                                            /**/            ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  fd_exec_instr_ctx_t const * instr_ctx = vm->instr_ctx;
  if( FD_UNLIKELY( !instr_ctx ) ) return FD_VM_SYSCALL_ERR_OUTSIDE_RUNTIME;

  FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( FD_VM_SYSVAR_BASE_COST, sizeof(fd_sysvar_epoch_rewards_t) ) );

  void * out = FD_VM_MEM_HADDR_ST( vm, out_vaddr, FD_VM_ALIGN_RUST_SYSVAR_EPOCH_REWARDS, sizeof(fd_sysvar_epoch_rewards_t) );

  fd_sysvar_epoch_rewards_t const * epoch_rewards = fd_sysvar_epoch_rewards_read( instr_ctx->txn_ctx->funk,
                                                                                  instr_ctx->txn_ctx->funk_txn,
                                                                                  instr_ctx->txn_ctx->spad );
  if( FD_UNLIKELY( !epoch_rewards ) ) {
    FD_LOG_ERR(( "failed to read sysvar epoch rewards" ));
  }

  memcpy( out, epoch_rewards, sizeof(fd_sysvar_epoch_rewards_t) );

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}
