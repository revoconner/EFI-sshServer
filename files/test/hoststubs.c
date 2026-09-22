/* Host side replacements for uefirt.c so ssh.c can run as a normal Windows process. */

#include "../uefirt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

void host_sleep_us(unsigned long long us);
int  host_random(unsigned char *out, unsigned int sz);

static EFI_STATUS EFIAPI StubStall(UINTN us)
{
    host_sleep_us(us);
    return EFI_SUCCESS;
}

static EFI_BOOT_SERVICES mBs;
BOOLEAN gDebug = FALSE;

UINT64 RtNow(void)
{
    return (UINT64)(__rdtsc() / 3000000000ULL);
}

BOOLEAN RtTimedOut(UINT64 startSec, UINTN spins, UINTN usPerSpin, UINTN limitMs)
{
    (void)startSec;
    return (BOOLEAN)(spins * usPerSpin > limitMs * 1000 * 4);
}
EFI_SYSTEM_TABLE     *gST;
EFI_BOOT_SERVICES    *gBS = &mBs;
EFI_RUNTIME_SERVICES *gRT;
EFI_HANDLE            gImageHandle;

void RtInit(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    (void)ImageHandle;
    (void)SystemTable;
    mBs.Stall = StubStall;
}

void *RtAlloc(UINTN size)
{
    return malloc(size ? size : 1);
}

void *RtAllocZero(UINTN size)
{
    return calloc(1, size ? size : 1);
}

void RtFree(void *p)
{
    free(p);
}

void *XMALLOC(size_t n, void *heap, int type)
{
    (void)heap;
    (void)type;
    return malloc(n ? n : 1);
}

void XFREE(void *p, void *heap, int type)
{
    (void)heap;
    (void)type;
    free(p);
}

void *XREALLOC(void *p, size_t n, void *heap, int type)
{
    (void)heap;
    (void)type;
    return realloc(p, n);
}

UINT64 RtTicks(void)
{
    return __rdtsc();
}

int UefiRandSeed(unsigned char *out, unsigned int sz)
{
    return host_random(out, sz);
}

/* Same subset of conversions as the UEFI Print. */
void Print(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    while (*fmt != 0) {
        char c = *fmt++;
        if (c != '%') {
            putchar(c);
            continue;
        }
        c = *fmt++;
        switch (c) {
        case 'd': printf("%d", va_arg(ap, int)); break;
        case 'u': printf("%u", va_arg(ap, unsigned)); break;
        case 'x': printf("%x", va_arg(ap, unsigned)); break;
        case 'r': printf("%llx", va_arg(ap, unsigned long long)); break;
        case 'c': putchar(va_arg(ap, int)); break;
        case 's': printf("%s", va_arg(ap, const char *)); break;
        case 'l':
            if (*fmt == 'x') { fmt++; printf("%llx", va_arg(ap, unsigned long long)); }
            else if (*fmt == 'u') { fmt++; printf("%llu", va_arg(ap, unsigned long long)); }
            break;
        case '%': putchar('%'); break;
        default: putchar('%'); putchar(c); break;
        }
    }
    va_end(ap);
    fflush(stdout);
}
