/* TCP4 listener and connection on the UEFI network stack. Blocking calls spin on Poll so they work at TPL_APPLICATION and TPL_CALLBACK. */

#ifndef SSH_NET_H_
#define SSH_NET_H_

#include "uefi.h"

#define NET_RX_SIZE 16384

typedef struct {
    EFI_TCP4_PROTOCOL     *Tcp;
    EFI_HANDLE             Handle;
    EFI_TCP4_IO_TOKEN      RxTok;
    EFI_TCP4_RECEIVE_DATA  RxData;
    UINT8                  RxBuf[NET_RX_SIZE];
    BOOLEAN                RxPosted;
    UINTN                  RxAvail;
    UINTN                  RxOff;
    BOOLEAN                Closed;
    EFI_IPv4_ADDRESS       Remote;
    UINT16                 RemotePort;
} NET_CONN;

/* Binds the listener on the default station address. Retries while DHCP is still running. */
EFI_STATUS NetListenStart(UINT16 port);
void       NetListenStop(void);

/* Waits for a client. Returns EFI_ABORTED if the user pressed ESC or q on the local console. */
EFI_STATUS NetAccept(NET_CONN *conn);

/* IO callbacks for the SSH layer. ctx is a NET_CONN pointer. */
int  NetRead(void *ctx, UINT8 *buf, UINTN max);
int  NetWrite(void *ctx, const UINT8 *buf, UINTN len);

void NetCloseConn(NET_CONN *conn);

/* Non blocking check of the local keyboard. Returns TRUE when ESC or q was pressed. */
BOOLEAN NetLocalAbortRequested(void);

#endif
