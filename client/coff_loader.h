/* coff_loader.h - BOF (Beacon Object File) loader for Dragon C2
 *
 * Include AFTER the ExecMemCtx typedef in client.c
 * Requires: no extra libs (uses kernel32/advapi32 already linked)
 */
#ifndef COFF_LOADER_H
#define COFF_LOADER_H
 
#include <stdint.h>
 
/* Detect if raw bytes are a COFF object file (not a PE) */
int is_coff_bof(const uint8_t *data, uint64_t size);
 
/* Load and execute a BOF in the current process */
void exec_bof_in_process(ExecMemCtx *ctx);
 
#endif /* COFF_LOADER_H */