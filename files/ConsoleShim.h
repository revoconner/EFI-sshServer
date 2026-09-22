/* Console shim: SimpleTextIn, SimpleTextInEx and SimpleTextOut backed by an SSH channel. The EDK2 Shell reads keys from gST->ConIn and writes to gST->ConOut without caring where they go, so we swap in these, launch a nested Shell, and put the originals back when it exits. Same trick a serial console redirect uses. */

#ifndef SSH_CONSOLE_SHIM_H_
#define SSH_CONSOLE_SHIM_H_

#include "uefi.h"
#include "ssh.h"

#define SHIM_KEY_RING   256
#define SHIM_MAX_NOTIFY 16
#define SHIM_OUT_BUF    2048

typedef struct {
    EFI_KEY_DATA            Key;
    EFI_KEY_NOTIFY_FUNCTION Fn;
    BOOLEAN                 Used;
} SHIM_NOTIFY;

typedef struct {
    SSH_CONN                         *Ssh;

    EFI_SIMPLE_TEXT_INPUT_PROTOCOL    TextIn;
    EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL TextInEx;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL   TextOut;
    SIMPLE_TEXT_OUTPUT_MODE           Mode;
    EFI_HANDLE                        Handle;

    EFI_KEY_DATA Keys[SHIM_KEY_RING];
    UINTN        KeyHead;
    UINTN        KeyTail;
    UINT8        Esc[24];
    UINTN        EscLen;
    UINT64       EscTick;
    UINT32       Utf8Acc;
    int          Utf8Need;
    BOOLEAN      LastWasCr;
    SHIM_NOTIFY  Notify[SHIM_MAX_NOTIFY];

    UINT32       Cols;
    UINT32       Rows;
    BOOLEAN      PendingWrap;
    UINT8        OutBuf[SHIM_OUT_BUF];
    UINTN        OutLen;
    UINTN        OutPoll;

    BOOLEAN      Disconnected;
    UINTN        ExitInjects;

    EFI_SIMPLE_TEXT_INPUT_PROTOCOL  *OldConIn;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *OldConOut;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *OldStdErr;
    EFI_HANDLE                       OldInHandle;
    EFI_HANDLE                       OldOutHandle;
    EFI_HANDLE                       OldErrHandle;
    BOOLEAN                          Installed;
} CONSOLE_SHIM;

/* Builds the protocols and swaps them into the system table. */
EFI_STATUS ShimInstall(CONSOLE_SHIM *S, SSH_CONN *ssh);

/* Restores the original console. Call after the nested Shell exits. */
VOID ShimRemove(CONSOLE_SHIM *S);

#endif
