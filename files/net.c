/* TCP4 listener and connection on the UEFI network stack. Every wait spins on Poll plus CheckEvent, which is legal at TPL_APPLICATION and TPL_CALLBACK, so the SSH pump can run from the console shim's WaitForKey notify as well as from ReadKeyStroke. */

#include "net.h"
#include "uefirt.h"
#include <string.h>

static EFI_SERVICE_BINDING_PROTOCOL  *mSb;
static EFI_HANDLE                     mListenHandle;
static EFI_TCP4_PROTOCOL             *mListen;
static EFI_SIMPLE_TEXT_INPUT_PROTOCOL *mLocalIn;

BOOLEAN NetLocalAbortRequested(void)
{
    EFI_INPUT_KEY k;
    if (mLocalIn == NULL) {
        return FALSE;
    }
    while (mLocalIn->ReadKeyStroke(mLocalIn, &k) == EFI_SUCCESS) {
        if (k.ScanCode == SCAN_ESC || k.UnicodeChar == 'q' || k.UnicodeChar == 'Q') {
            return TRUE;
        }
    }
    return FALSE;
}

static EFI_STATUS MakeEvent(EFI_EVENT *ev)
{
    return gBS->CreateEvent(0, TPL_CALLBACK, NULL, NULL, ev);
}

/* Spins until the token completes. timeoutMs of 0 means forever. */
static EFI_STATUS WaitToken(EFI_TCP4_PROTOCOL *tcp, EFI_TCP4_COMPLETION_TOKEN *tok, UINTN timeoutMs)
{
    UINTN  spins = 0;
    UINT64 start = RtNow();
    for (;;) {
        tcp->Poll(tcp);
        if (gBS->CheckEvent(tok->Event) == EFI_SUCCESS) {
            return tok->Status;
        }
        if (tok->Status != EFI_NOT_READY && (spins & 1023) == 1023 && gDebug) {
            Print("net: token status %r but event not signaled\n", tok->Status);
        }
        gBS->Stall(100);
        spins++;
        if (timeoutMs != 0 && RtTimedOut(start, spins, 100, timeoutMs)) {
            return EFI_TIMEOUT;
        }
    }
}

EFI_STATUS NetListenStart(UINT16 port)
{
    EFI_STATUS           st;
    EFI_TCP4_CONFIG_DATA cfg;
    UINTN                tries;

    mLocalIn = gST->ConIn;
    st = gBS->LocateProtocol(&gEfiTcp4ServiceBindingProtocolGuid, NULL, (VOID **)&mSb);
    if (EFI_ERROR(st) || mSb == NULL) {
        Print("No TCP4 service binding found. The firmware network stack is not loaded.\n");
        return EFI_NOT_FOUND;
    }
    mListenHandle = NULL;
    st = mSb->CreateChild(mSb, &mListenHandle);
    if (EFI_ERROR(st)) {
        Print("TCP4 CreateChild failed: %r\n", st);
        return st;
    }
    st = gBS->OpenProtocol(mListenHandle, &gEfiTcp4ProtocolGuid, (VOID **)&mListen, gImageHandle, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    if (EFI_ERROR(st)) {
        mSb->DestroyChild(mSb, mListenHandle);
        mListenHandle = NULL;
        return st;
    }

    memset(&cfg, 0, sizeof(cfg));
    cfg.TypeOfService = 0;
    cfg.TimeToLive = 64;
    cfg.AccessPoint.UseDefaultAddress = TRUE;
    cfg.AccessPoint.StationPort = port;
    cfg.AccessPoint.ActiveFlag = FALSE;
    cfg.ControlOption = NULL;

    for (tries = 0; tries < 240; tries++) {
        st = mListen->Configure(mListen, &cfg);
        if (st != EFI_NO_MAPPING) {
            break;
        }
        if (tries == 0) {
            Print("Waiting for an IP address. If this never finishes, run: ifconfig -s eth0 dhcp\n");
        }
        if (NetLocalAbortRequested()) {
            st = EFI_ABORTED;
            break;
        }
        gBS->Stall(500000);
    }
    if (EFI_ERROR(st)) {
        Print("TCP4 Configure failed: %r\n", st);
        NetListenStop();
        return st;
    }

    memset(&cfg, 0, sizeof(cfg));
    if (!EFI_ERROR(mListen->GetModeData(mListen, NULL, &cfg, NULL, NULL, NULL))) {
        Print("Listening on %d.%d.%d.%d port %u\n",
              cfg.AccessPoint.StationAddress.Addr[0], cfg.AccessPoint.StationAddress.Addr[1],
              cfg.AccessPoint.StationAddress.Addr[2], cfg.AccessPoint.StationAddress.Addr[3], port);
    } else {
        Print("Listening on port %u\n", port);
    }
    return EFI_SUCCESS;
}

void NetListenStop(void)
{
    if (mListen != NULL) {
        mListen->Configure(mListen, NULL);
    }
    if (mSb != NULL && mListenHandle != NULL) {
        mSb->DestroyChild(mSb, mListenHandle);
    }
    mListen = NULL;
    mListenHandle = NULL;
}

EFI_STATUS NetAccept(NET_CONN *conn)
{
    EFI_TCP4_LISTEN_TOKEN tok;
    EFI_TCP4_CONFIG_DATA  cfg;
    EFI_STATUS            st;
    UINTN                 i;

    memset(&tok, 0, sizeof(tok));
    st = MakeEvent(&tok.CompletionToken.Event);
    if (EFI_ERROR(st)) {
        return st;
    }
    tok.CompletionToken.Status = EFI_NOT_READY;
    st = mListen->Accept(mListen, &tok);
    if (EFI_ERROR(st)) {
        Print("TCP4 Accept failed: %r\n", st);
        gBS->CloseEvent(tok.CompletionToken.Event);
        return st;
    }
    for (;;) {
        mListen->Poll(mListen);
        if (gBS->CheckEvent(tok.CompletionToken.Event) == EFI_SUCCESS) {
            break;
        }
        if (NetLocalAbortRequested()) {
            mListen->Cancel(mListen, &tok.CompletionToken);
            for (i = 0; i < 100; i++) {
                mListen->Poll(mListen);
                if (gBS->CheckEvent(tok.CompletionToken.Event) == EFI_SUCCESS) {
                    break;
                }
                gBS->Stall(1000);
            }
            gBS->CloseEvent(tok.CompletionToken.Event);
            return EFI_ABORTED;
        }
        gBS->Stall(1000);
    }
    gBS->CloseEvent(tok.CompletionToken.Event);
    st = tok.CompletionToken.Status;
    if (EFI_ERROR(st)) {
        Print("Accept completed with %r\n", st);
        return st;
    }

    memset(conn, 0, sizeof(*conn));
    conn->Handle = tok.NewChildHandle;
    st = gBS->OpenProtocol(conn->Handle, &gEfiTcp4ProtocolGuid, (VOID **)&conn->Tcp, gImageHandle, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    if (EFI_ERROR(st)) {
        mSb->DestroyChild(mSb, conn->Handle);
        conn->Handle = NULL;
        return st;
    }
    memset(&cfg, 0, sizeof(cfg));
    if (!EFI_ERROR(conn->Tcp->GetModeData(conn->Tcp, NULL, &cfg, NULL, NULL, NULL))) {
        conn->Remote = cfg.AccessPoint.RemoteAddress;
        conn->RemotePort = cfg.AccessPoint.RemotePort;
    }
    st = MakeEvent(&conn->RxTok.CompletionToken.Event);
    if (EFI_ERROR(st)) {
        NetCloseConn(conn);
        return st;
    }
    return EFI_SUCCESS;
}

static void PostReceive(NET_CONN *conn)
{
    EFI_STATUS st;
    conn->RxData.UrgentFlag = FALSE;
    conn->RxData.DataLength = NET_RX_SIZE;
    conn->RxData.FragmentCount = 1;
    conn->RxData.FragmentTable[0].FragmentLength = NET_RX_SIZE;
    conn->RxData.FragmentTable[0].FragmentBuffer = conn->RxBuf;
    conn->RxTok.Packet.RxData = &conn->RxData;
    conn->RxTok.CompletionToken.Status = EFI_NOT_READY;
    st = conn->Tcp->Receive(conn->Tcp, &conn->RxTok);
    if (EFI_ERROR(st)) {
        if (gDebug) {
            Print("net: Receive post failed %r\n", st);
        }
        conn->Closed = TRUE;
        return;
    }
    conn->RxPosted = TRUE;
}

int NetRead(void *ctx, UINT8 *buf, UINTN max)
{
    NET_CONN *conn = ctx;
    UINTN     n;

    if (conn->Tcp == NULL) {
        return -1;
    }
    if (conn->RxAvail == 0) {
        if (!conn->RxPosted && !conn->Closed) {
            PostReceive(conn);
        }
        conn->Tcp->Poll(conn->Tcp);
        if (conn->RxPosted && gBS->CheckEvent(conn->RxTok.CompletionToken.Event) == EFI_SUCCESS) {
            EFI_STATUS st = conn->RxTok.CompletionToken.Status;
            conn->RxPosted = FALSE;
            if (gDebug) {
                Print("net: rx done %r, %u bytes\n", st, conn->RxData.DataLength);
            }
            if (EFI_ERROR(st)) {
                conn->Closed = TRUE;
            } else {
                conn->RxAvail = conn->RxData.DataLength;
                if (conn->RxAvail > NET_RX_SIZE) {
                    conn->RxAvail = NET_RX_SIZE;
                }
                conn->RxOff = 0;
            }
        }
    }
    if (conn->RxAvail == 0) {
        return conn->Closed ? -1 : 0;
    }
    n = conn->RxAvail < max ? conn->RxAvail : max;
    memcpy(buf, conn->RxBuf + conn->RxOff, n);
    conn->RxOff += n;
    conn->RxAvail -= n;
    return (int)n;
}

int NetWrite(void *ctx, const UINT8 *buf, UINTN len)
{
    NET_CONN              *conn = ctx;
    EFI_TCP4_IO_TOKEN      tok;
    EFI_TCP4_TRANSMIT_DATA td;
    EFI_STATUS             st;

    if (conn->Tcp == NULL || conn->Closed) {
        return -1;
    }
    while (len > 0) {
        UINTN chunk = len > 8192 ? 8192 : len;
        memset(&tok, 0, sizeof(tok));
        memset(&td, 0, sizeof(td));
        if (EFI_ERROR(MakeEvent(&tok.CompletionToken.Event))) {
            return -1;
        }
        tok.CompletionToken.Status = EFI_NOT_READY;
        td.Push = TRUE;
        td.Urgent = FALSE;
        td.DataLength = (UINT32)chunk;
        td.FragmentCount = 1;
        td.FragmentTable[0].FragmentLength = (UINT32)chunk;
        td.FragmentTable[0].FragmentBuffer = (VOID *)buf;
        tok.Packet.TxData = &td;
        st = conn->Tcp->Transmit(conn->Tcp, &tok);
        if (gDebug) {
            Print("net: tx %u bytes posted %r\n", (unsigned)chunk, st);
        }
        if (!EFI_ERROR(st)) {
            st = WaitToken(conn->Tcp, &tok.CompletionToken, 30000);
            if (st == EFI_TIMEOUT) {
                conn->Tcp->Cancel(conn->Tcp, &tok.CompletionToken);
                WaitToken(conn->Tcp, &tok.CompletionToken, 1000);
            }
            if (gDebug) {
                Print("net: tx done %r\n", st);
            }
        }
        gBS->CloseEvent(tok.CompletionToken.Event);
        if (EFI_ERROR(st)) {
            Print("net: transmit failed %r\n", st);
            conn->Closed = TRUE;
            return -1;
        }
        buf += chunk;
        len -= chunk;
    }
    return 0;
}

void NetCloseConn(NET_CONN *conn)
{
    if (conn->Tcp == NULL) {
        return;
    }
    if (conn->RxPosted) {
        conn->Tcp->Cancel(conn->Tcp, &conn->RxTok.CompletionToken);
        WaitToken(conn->Tcp, &conn->RxTok.CompletionToken, 500);
        conn->RxPosted = FALSE;
    }
    if (!conn->Closed) {
        EFI_TCP4_CLOSE_TOKEN ct;
        memset(&ct, 0, sizeof(ct));
        if (!EFI_ERROR(MakeEvent(&ct.CompletionToken.Event))) {
            ct.AbortOnClose = FALSE;
            if (!EFI_ERROR(conn->Tcp->Close(conn->Tcp, &ct))) {
                WaitToken(conn->Tcp, &ct.CompletionToken, 3000);
            }
            gBS->CloseEvent(ct.CompletionToken.Event);
        }
        conn->Closed = TRUE;
    }
    if (conn->RxTok.CompletionToken.Event != NULL) {
        gBS->CloseEvent(conn->RxTok.CompletionToken.Event);
        conn->RxTok.CompletionToken.Event = NULL;
    }
    if (mSb != NULL && conn->Handle != NULL) {
        mSb->DestroyChild(mSb, conn->Handle);
    }
    conn->Handle = NULL;
    conn->Tcp = NULL;
}
