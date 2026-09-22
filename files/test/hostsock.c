/* Winsock helpers for the host test. Kept in its own file so windows.h never meets uefi.h. */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>

static SOCKET mListen = INVALID_SOCKET;
static SOCKET mConn = INVALID_SOCKET;

int sock_listen(unsigned short port)
{
    WSADATA wsa;
    struct sockaddr_in sa;
    BOOL yes = TRUE;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return -1;
    }
    mListen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (mListen == INVALID_SOCKET) {
        return -1;
    }
    setsockopt(mListen, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(mListen, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(mListen, 4) != 0) {
        printf("bind/listen failed: %d\n", WSAGetLastError());
        return -1;
    }
    return 0;
}

int sock_accept(void)
{
    u_long nb = 1;
    mConn = accept(mListen, NULL, NULL);
    if (mConn == INVALID_SOCKET) {
        return -1;
    }
    ioctlsocket(mConn, FIONBIO, &nb);
    return 0;
}

/* Returns bytes, 0 when nothing is pending, -1 when closed. */
int sock_recv_nb(void *ctx, unsigned char *buf, unsigned long long max)
{
    int n;
    (void)ctx;
    n = recv(mConn, (char *)buf, (int)(max > 65536 ? 65536 : max), 0);
    if (n > 0) {
        return n;
    }
    if (n == 0) {
        return -1;
    }
    return WSAGetLastError() == WSAEWOULDBLOCK ? 0 : -1;
}

int sock_send_all(void *ctx, const unsigned char *buf, unsigned long long len)
{
    (void)ctx;
    while (len > 0) {
        int n = send(mConn, (const char *)buf, (int)(len > 65536 ? 65536 : len), 0);
        if (n > 0) {
            buf += n;
            len -= (unsigned long long)n;
            continue;
        }
        if (n < 0 && WSAGetLastError() == WSAEWOULDBLOCK) {
            Sleep(1);
            continue;
        }
        return -1;
    }
    return 0;
}

void sock_close_conn(void)
{
    if (mConn != INVALID_SOCKET) {
        shutdown(mConn, SD_BOTH);
        closesocket(mConn);
        mConn = INVALID_SOCKET;
    }
}

void host_sleep_us(unsigned long long us)
{
    Sleep((DWORD)(us / 1000 == 0 ? 1 : us / 1000));
}

int host_random(unsigned char *out, unsigned int sz)
{
    HMODULE h = LoadLibraryA("advapi32.dll");
    typedef BOOLEAN (WINAPI *RtlGenRandomFn)(PVOID, ULONG);
    RtlGenRandomFn fn;
    if (h == NULL) {
        return -1;
    }
    fn = (RtlGenRandomFn)GetProcAddress(h, "SystemFunction036");
    if (fn == NULL || !fn(out, sz)) {
        return -1;
    }
    return 0;
}
