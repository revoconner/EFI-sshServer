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

/* Wall clock seconds from GetTime, only good for measuring elapsed time. Returns 0 if GetTime fails. */
UINT64 RtNow(void);

/* Timeout check that works even when Stall is coarse or GetTime is broken: true once the wall clock says limitMs passed, or once spins times usPerSpin is four times over the limit. */
BOOLEAN RtTimedOut(UINT64 startSec, UINTN spins, UINTN usPerSpin, UINTN limitMs);

/* Set by -d on the command line. Turns on per packet tracing on the local console. */
extern BOOLEAN gDebug;

/* Prints a frame pointer backtrace as image offsets and halts. */
void RtBacktrace(const char *why);

#endif
