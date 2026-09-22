/* SSH 2.0 server transport, user auth and a single session channel, built on wolfCrypt. Cooperative and non blocking: the caller pumps it from its own loop. */

#ifndef SSH_SERVER_H_
#define SSH_SERVER_H_

#include "uefi.h"

/* Returns the number of bytes read, 0 when nothing is pending, -1 when the connection is gone. */
typedef int (*SSH_IO_READ)(void *ctx, UINT8 *buf, UINTN max);

/* Sends everything or fails. Returns 0 on success, -1 on error. */
typedef int (*SSH_IO_WRITE)(void *ctx, const UINT8 *buf, UINTN len);

/* Password check. Both strings are NUL terminated. */
typedef BOOLEAN (*SSH_AUTH_FN)(void *ctx, const char *user, const char *pass);

typedef struct SSH_CONN SSH_CONN;

SSH_CONN *SshNew(SSH_IO_READ rd, SSH_IO_WRITE wr, void *ioCtx, const UINT8 *hostSeed32, SSH_AUTH_FN auth, void *authCtx);
void SshFree(SSH_CONN *c);

/* Runs version exchange, key exchange, auth and channel setup. Returns 0 once the client asked for a shell, -1 if the connection ended first. */
int SshAccept(SSH_CONN *c);

/* Processes any pending input without blocking. Returns 0 normally, -1 once the connection is closed. */
int SshPoll(SSH_CONN *c);

/* Pulls decrypted terminal input. Returns bytes copied (may be 0), -1 when the channel or connection is gone. */
int SshRead(SSH_CONN *c, UINT8 *buf, UINTN max);

/* Sends terminal output over the channel. Returns 0 on success, -1 on failure. */
int SshWrite(SSH_CONN *c, const UINT8 *buf, UINTN len);

/* Sends exit status, closes the channel and disconnects. Safe to call in any state. */
void SshClose(SSH_CONN *c, UINT32 exitStatus);

BOOLEAN SshIsOpen(SSH_CONN *c);
void SshGetWindow(SSH_CONN *c, UINT32 *cols, UINT32 *rows);
const char *SshUser(SSH_CONN *c);

/* Prints the host key fingerprint on the local console. */
void SshPrintHostKey(const UINT8 *hostSeed32);

#endif
