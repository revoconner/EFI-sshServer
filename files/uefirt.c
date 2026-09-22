/* Runtime glue and the small C library subset that wolfCrypt and this project need. */

#include "uefirt.h"
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

EFI_SYSTEM_TABLE     *gST;
EFI_BOOT_SERVICES    *gBS;
EFI_RUNTIME_SERVICES *gRT;
EFI_HANDLE            gImageHandle;

static EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *mLocalOut;

EFI_GUID gEfiSimpleTextInProtocolGuid      = { 0x387477c1, 0x69c7, 0x11d2, { 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
EFI_GUID gEfiSimpleTextInputExProtocolGuid = { 0xdd9e7534, 0x7762, 0x4698, { 0x8c, 0x14, 0xf5, 0x85, 0x17, 0xa6, 0x25, 0xaa } };
EFI_GUID gEfiSimpleTextOutProtocolGuid     = { 0x387477c2, 0x69c7, 0x11d2, { 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
EFI_GUID gEfiLoadedImageProtocolGuid       = { 0x5b1b31a1, 0x9562, 0x11d2, { 0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
EFI_GUID gEfiDevicePathProtocolGuid        = { 0x09576e91, 0x6d3f, 0x11d2, { 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
EFI_GUID gEfiTcp4ServiceBindingProtocolGuid = { 0x00720665, 0x67eb, 0x4a99, { 0xba, 0xf7, 0xd3, 0xc3, 0x3a, 0x1c, 0x7c, 0xc9 } };
EFI_GUID gEfiTcp4ProtocolGuid              = { 0x65530bc7, 0xa359, 0x410f, { 0xb0, 0x10, 0x5a, 0xad, 0xc7, 0xec, 0x2b, 0x62 } };
EFI_GUID gEfiFirmwareVolume2ProtocolGuid   = { 0x220e73b6, 0x6bdb, 0x4413, { 0x84, 0x05, 0xb9, 0x74, 0xb1, 0x08, 0x61, 0x9a } };
EFI_GUID gEfiRngProtocolGuid               = { 0x3152bca5, 0xeade, 0x433d, { 0x86, 0x2e, 0xc0, 0x1c, 0xdc, 0x29, 0x1f, 0x44 } };

/* Referenced by clang if any floating point sneaks in. */
int _fltused = 0;

void RtInit(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    gST = SystemTable;
    gBS = SystemTable->BootServices;
    gRT = SystemTable->RuntimeServices;
    gImageHandle = ImageHandle;
    mLocalOut = SystemTable->ConOut;
}

void *RtAlloc(UINTN size)
{
    void *p = NULL;
    if (size == 0) {
        size = 1;
    }
    if (EFI_ERROR(gBS->AllocatePool(EfiBootServicesData, size, &p))) {
        return NULL;
    }
    return p;
}

void *RtAllocZero(UINTN size)
{
    void *p = RtAlloc(size);
    if (p != NULL) {
        memset(p, 0, size);
    }
    return p;
}

void RtFree(void *p)
{
    if (p != NULL) {
        gBS->FreePool(p);
    }
}

/* wolfCrypt heap hooks, see user_settings.h. Realloc has no size query in UEFI, so a small header stores it. */

void *XMALLOC(size_t n, void *heap, int type)
{
    UINTN *p;
    (void)heap;
    (void)type;
    p = RtAlloc(n + 16);
    if (p == NULL) {
        return NULL;
    }
    p[0] = n;
    return p + 2;
}

void XFREE(void *p, void *heap, int type)
{
    (void)heap;
    (void)type;
    if (p != NULL) {
        RtFree((UINTN *)p - 2);
    }
}

void *XREALLOC(void *p, size_t n, void *heap, int type)
{
    void *q;
    UINTN old;
    if (p == NULL) {
        return XMALLOC(n, heap, type);
    }
    old = ((UINTN *)p)[-2];
    q = XMALLOC(n, heap, type);
    if (q == NULL) {
        return NULL;
    }
    memcpy(q, p, old < n ? old : n);
    XFREE(p, heap, type);
    return q;
}

/* Tiny printf. Enough for status lines on the local console. */

static void PutNum(CHAR16 **w, CHAR16 *end, UINT64 v, unsigned base, int neg)
{
    CHAR16 tmp[24];
    int n = 0;
    do {
        unsigned d = (unsigned)(v % base);
        tmp[n++] = (CHAR16)(d < 10 ? '0' + d : 'a' + d - 10);
        v /= base;
    } while (v != 0);
    if (neg && *w < end) {
        *(*w)++ = '-';
    }
    while (n > 0 && *w < end) {
        *(*w)++ = tmp[--n];
    }
}

void Print(const char *fmt, ...)
{
    CHAR16 buf[512];
    CHAR16 *w = buf;
    CHAR16 *end = buf + 510;
    va_list ap;

    if (mLocalOut == NULL) {
        return;
    }
    va_start(ap, fmt);
    while (*fmt != 0 && w < end) {
        char c = *fmt++;
        if (c != '%') {
            if (c == '\n') {
                *w++ = '\r';
            }
            *w++ = (CHAR16)(unsigned char)c;
            continue;
        }
        c = *fmt++;
        switch (c) {
        case 'd': {
            int v = va_arg(ap, int);
            PutNum(&w, end, (UINT64)(v < 0 ? -(INT64)v : v), 10, v < 0);
            break;
        }
        case 'u':
            PutNum(&w, end, va_arg(ap, unsigned), 10, 0);
            break;
        case 'x':
            PutNum(&w, end, va_arg(ap, unsigned), 16, 0);
            break;
        case 'l':
            if (*fmt == 'x') {
                fmt++;
                PutNum(&w, end, va_arg(ap, UINT64), 16, 0);
            } else if (*fmt == 'u') {
                fmt++;
                PutNum(&w, end, va_arg(ap, UINT64), 10, 0);
            }
            break;
        case 'r':
            PutNum(&w, end, va_arg(ap, UINT64), 16, 0);
            break;
        case 'c':
            *w++ = (CHAR16)va_arg(ap, int);
            break;
        case 's': {
            const char *s = va_arg(ap, const char *);
            if (s == NULL) {
                s = "(null)";
            }
            while (*s != 0 && w < end) {
                *w++ = (CHAR16)(unsigned char)*s++;
            }
            break;
        }
        case '%':
            *w++ = '%';
            break;
        default:
            *w++ = '%';
            if (w < end) {
                *w++ = (CHAR16)(unsigned char)c;
            }
            break;
        }
    }
    va_end(ap);
    *w = 0;
    mLocalOut->OutputString(mLocalOut, buf);
}

/* Entropy. Firmware RNG protocol first, then RDRAND, always mixed with TSC jitter so a missing source still moves the seed. */

UINT64 RtTicks(void)
{
    UINT32 lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((UINT64)hi << 32) | lo;
}

static int HaveRdrand(void)
{
    UINT32 a, b, c, d;
    __asm__ volatile ("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1), "c"(0));
    return (c >> 30) & 1;
}

static int Rdrand64(UINT64 *out)
{
    int i;
    for (i = 0; i < 16; i++) {
        unsigned char ok;
        UINT64 v;
        __asm__ volatile ("rdrand %0; setc %1" : "=r"(v), "=qm"(ok));
        if (ok) {
            *out = v;
            return 1;
        }
    }
    return 0;
}

int UefiRandSeed(unsigned char *out, unsigned int sz)
{
    EFI_RNG_PROTOCOL *rng = NULL;
    unsigned int i;
    int haveSource = 0;

    memset(out, 0, sz);
    if (!EFI_ERROR(gBS->LocateProtocol(&gEfiRngProtocolGuid, NULL, (VOID **)&rng)) && rng != NULL) {
        if (!EFI_ERROR(rng->GetRNG(rng, NULL, sz, out))) {
            haveSource = 1;
        }
    }
    if (HaveRdrand()) {
        for (i = 0; i < sz; i += 8) {
            UINT64 v;
            unsigned int j;
            if (!Rdrand64(&v)) {
                break;
            }
            for (j = 0; j < 8 && i + j < sz; j++) {
                out[i + j] ^= (unsigned char)(v >> (8 * j));
            }
            haveSource = 1;
        }
    }
    /* Jitter mixing. Weak on its own, so it only supplements the sources above. */
    for (i = 0; i < sz; i++) {
        UINT64 t = RtTicks();
        EFI_TIME now;
        gBS->Stall(37 + (i % 7));
        out[i] ^= (unsigned char)(t ^ (t >> 8) ^ (t >> 16) ^ (RtTicks() * 0x9E3779B97F4A7C15ULL >> 56));
        if (i == 0 && gRT != NULL && !EFI_ERROR(gRT->GetTime(&now, NULL))) {
            out[i] ^= (unsigned char)(now.Second ^ now.Minute ^ (now.Nanosecond >> 3));
        }
    }
    return haveSource ? 0 : -1;
}

/* C library subset. Byte loops on purpose, no libc exists here. */

void *memcpy(void *d, const void *s, size_t n)
{
    unsigned char *dd = d;
    const unsigned char *ss = s;
    while (n-- > 0) {
        *dd++ = *ss++;
    }
    return d;
}

void *memmove(void *d, const void *s, size_t n)
{
    unsigned char *dd = d;
    const unsigned char *ss = s;
    if (dd == ss || n == 0) {
        return d;
    }
    if (dd < ss) {
        while (n-- > 0) {
            *dd++ = *ss++;
        }
    } else {
        dd += n;
        ss += n;
        while (n-- > 0) {
            *--dd = *--ss;
        }
    }
    return d;
}

void *memset(void *d, int c, size_t n)
{
    unsigned char *dd = d;
    while (n-- > 0) {
        *dd++ = (unsigned char)c;
    }
    return d;
}

int memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *x = a;
    const unsigned char *y = b;
    while (n-- > 0) {
        if (*x != *y) {
            return *x - *y;
        }
        x++;
        y++;
    }
    return 0;
}

void *memchr(const void *s, int c, size_t n)
{
    const unsigned char *p = s;
    while (n-- > 0) {
        if (*p == (unsigned char)c) {
            return (void *)p;
        }
        p++;
    }
    return NULL;
}

size_t strlen(const char *s)
{
    size_t n = 0;
    while (s[n] != 0) {
        n++;
    }
    return n;
}

int strcmp(const char *a, const char *b)
{
    while (*a != 0 && *a == *b) {
        a++;
        b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

int strncmp(const char *a, const char *b, size_t n)
{
    while (n-- > 0) {
        if (*a != *b || *a == 0) {
            return (unsigned char)*a - (unsigned char)*b;
        }
        a++;
        b++;
    }
    return 0;
}

char *strncpy(char *d, const char *s, size_t n)
{
    size_t i = 0;
    while (i < n && s[i] != 0) {
        d[i] = s[i];
        i++;
    }
    while (i < n) {
        d[i++] = 0;
    }
    return d;
}

char *strcpy(char *d, const char *s)
{
    char *r = d;
    while ((*d++ = *s++) != 0) {
    }
    return r;
}

char *strcat(char *d, const char *s)
{
    strcpy(d + strlen(d), s);
    return d;
}

char *strchr(const char *s, int c)
{
    while (*s != 0) {
        if (*s == (char)c) {
            return (char *)s;
        }
        s++;
    }
    return c == 0 ? (char *)s : NULL;
}

char *strrchr(const char *s, int c)
{
    const char *r = NULL;
    while (*s != 0) {
        if (*s == (char)c) {
            r = s;
        }
        s++;
    }
    return (char *)r;
}

char *strstr(const char *h, const char *n)
{
    size_t nl = strlen(n);
    if (nl == 0) {
        return (char *)h;
    }
    while (*h != 0) {
        if (strncmp(h, n, nl) == 0) {
            return (char *)h;
        }
        h++;
    }
    return NULL;
}

int strncasecmp(const char *a, const char *b, size_t n)
{
    while (n-- > 0) {
        int x = tolower((unsigned char)*a);
        int y = tolower((unsigned char)*b);
        if (x != y || x == 0) {
            return x - y;
        }
        a++;
        b++;
    }
    return 0;
}

int strcasecmp(const char *a, const char *b)
{
    return strncasecmp(a, b, (size_t)-1);
}

int toupper(int c)
{
    return (c >= 'a' && c <= 'z') ? c - 32 : c;
}

int tolower(int c)
{
    return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

int isspace(int c)
{
    return c == ' ' || (c >= 9 && c <= 13);
}

int isdigit(int c)
{
    return c >= '0' && c <= '9';
}

int isalpha(int c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

int isalnum(int c)
{
    return isalpha(c) || isdigit(c);
}

int isupper(int c)
{
    return c >= 'A' && c <= 'Z';
}

int islower(int c)
{
    return c >= 'a' && c <= 'z';
}

int isxdigit(int c)
{
    return isdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

int atoi(const char *s)
{
    int v = 0;
    int neg = 0;
    while (isspace((unsigned char)*s)) {
        s++;
    }
    if (*s == '-') {
        neg = 1;
        s++;
    } else if (*s == '+') {
        s++;
    }
    while (isdigit((unsigned char)*s)) {
        v = v * 10 + (*s++ - '0');
    }
    return neg ? -v : v;
}

void abort(void)
{
    Print("abort() called\n");
    for (;;) {
        gBS->Stall(1000000);
    }
}
