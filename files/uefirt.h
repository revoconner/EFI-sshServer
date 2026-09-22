/* Runtime glue: globals, tiny printf to the local console, allocation, entropy. */

#ifndef UEFI_RT_H_
#define UEFI_RT_H_

#include "uefi.h"

extern EFI_SYSTEM_TABLE     *gST;
extern EFI_BOOT_SERVICES    *gBS;
extern EFI_RUNTIME_SERVICES *gRT;
extern EFI_HANDLE            gImageHandle;

void RtInit(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable);

/* Formats %d %u %x %s %c %% into CHAR16 and writes to the console that was current at RtInit. Never goes through the SSH shim. */
void Print(const char *fmt, ...);

void *RtAlloc(UINTN size);
void *RtAllocZero(UINTN size);
void  RtFree(void *p);

/* Seed callback for wolfCrypt. Returns 0 on success. */
int UefiRandSeed(unsigned char *out, unsigned int sz);

/* Rough monotonic clock in TSC ticks. */
UINT64 RtTicks(void);

#endif
