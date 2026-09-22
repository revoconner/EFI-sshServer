/* Host test: runs the SSH server core on a loopback TCP port and serves a trivial echo shell, so real clients (OpenSSH, plink) can exercise the exact handshake, auth and channel code that ships in the EFI binary. Usage: hosttest [port] [sessions] */

#include "../uefirt.h"
#include "../ssh.h"
#include "../hostkey.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int  sock_listen(unsigned short port);
int  sock_accept(void);
int  sock_recv_nb(void *ctx, unsigned char *buf, unsigned long long max);
int  sock_send_all(void *ctx, const unsigned char *buf, unsigned long long len);
void sock_close_conn(void);

static BOOLEAN Auth(void *ctx, const char *user, const char *pass)
{
    (void)ctx;
    return (BOOLEAN)(strcmp(user, "admin") == 0 && strcmp(pass, "admin") == 0);
}

static int Send(SSH_CONN *c, const char *s)
{
    return SshWrite(c, (const UINT8 *)s, strlen(s));
}

static void Serve(SSH_CONN *c)
{
    char  line[256];
    UINTN lineLen = 0;
    UINT32 cols, rows;

    SshGetWindow(c, &cols, &rows);
    printf("host: terminal %ux%u\n", cols, rows);
    Send(c, "hosttest echo shell. Type exit to quit.\r\nhosttest> ");
    for (;;) {
        UINT8 buf[64];
        int n = SshRead(c, buf, sizeof(buf));
        int i;
        if (n < 0) {
            printf("host: channel closed by client\n");
            return;
        }
        if (n == 0) {
            gBS->Stall(1000);
            continue;
        }
        for (i = 0; i < n; i++) {
            UINT8 b = buf[i];
            if (b == '\r' || b == '\n') {
                char out[320];
                line[lineLen] = 0;
                if (strcmp(line, "exit") == 0) {
                    Send(c, "\r\nbye\r\n");
                    return;
                }
                if (strcmp(line, "big") == 0) {
                    /* Exercise window handling with more than one channel window of output. */
                    UINTN k;
                    Send(c, "\r\n");
                    for (k = 0; k < 3000; k++) {
                        snprintf(out, sizeof(out), "line %05u ---------------------------------------------------------------\r\n", (unsigned)k);
                        if (Send(c, out) != 0) {
                            printf("host: write failed at line %u\n", (unsigned)k);
                            return;
                        }
                    }
                    Send(c, "hosttest> ");
                } else {
                    snprintf(out, sizeof(out), "\r\nYou typed: %s\r\nhosttest> ", line);
                    Send(c, out);
                }
                lineLen = 0;
            } else if (b == 0x7f || b == 0x08) {
                if (lineLen > 0) {
                    lineLen--;
                    Send(c, "\b \b");
                }
            } else if (b >= 0x20 && lineLen + 1 < sizeof(line)) {
                char ch[2] = { (char)b, 0 };
                line[lineLen++] = (char)b;
                Send(c, ch);
            }
        }
    }
}

int main(int argc, char **argv)
{
    unsigned short port = (unsigned short)(argc > 1 ? atoi(argv[1]) : 2222);
    int sessions = argc > 2 ? atoi(argv[2]) : 1;
    int i;

    RtInit(NULL, NULL);
    SshPrintHostKey(HOST_KEY_SEED);
    if (sock_listen(port) != 0) {
        printf("listen failed\n");
        return 1;
    }
    printf("host: listening on 127.0.0.1:%u for %d session(s)\n", port, sessions);
    for (i = 0; i < sessions; i++) {
        SSH_CONN *c;
        if (sock_accept() != 0) {
            printf("accept failed\n");
            return 1;
        }
        printf("host: client connected\n");
        c = SshNew(sock_recv_nb, sock_send_all, NULL, HOST_KEY_SEED, Auth, NULL);
        if (c == NULL) {
            printf("SshNew failed\n");
            return 1;
        }
        if (SshAccept(c) == 0) {
            Serve(c);
        } else {
            printf("host: handshake failed\n");
        }
        SshClose(c, 0);
        SshFree(c);
        sock_close_conn();
        printf("host: session %d done\n", i + 1);
    }
    return 0;
}
