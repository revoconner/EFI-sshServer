/** @file
  Console shim: fake SimpleTextIn / SimpleTextOut backed by an SSH channel.

  The idea. The EDK2 Shell reads keys from gST->ConIn and writes to
  gST->ConOut. It has no idea where those go. So we build our own ConIn/ConOut
  that push bytes through wolfSSH instead of the local screen, swap the two
  pointers in the system table, then launch the Shell. It renders to the SSH
  client without any change to the Shell itself. Same trick serial redirect uses.
*/

#ifndef SSH_CONSOLE_SHIM_H_
#define SSH_CONSOLE_SHIM_H_

#include <Uefi.h>
#include <Protocol/SimpleTextIn.h>
#include <Protocol/SimpleTextOut.h>
#include <Protocol/Tcp4.h>

// wolfSSH. Comes from the port you build (see README).
#include <wolfssh/ssh.h>

#define RAW_RX_SIZE   4096   // ciphertext bytes drained from TCP, waiting for wolfSSH
#define PLAIN_SIZE    512    // decrypted bytes waiting to be turned into EFI keys
#define KEY_RING_SIZE 128    // decoded EFI keys waiting for the Shell to read
#define RX_SCRATCH    1024   // one TCP receive lands here

typedef struct {
  UINT8  Data[RAW_RX_SIZE];
  UINTN  Head;
  UINTN  Tail;
} BYTE_RING;

typedef struct {
  EFI_INPUT_KEY Key[KEY_RING_SIZE];
  UINTN         Head;
  UINTN         Tail;
} KEY_RING;

typedef struct {
  // network
  EFI_TCP4_PROTOCOL *Tcp;          // the connected socket (child from Accept)
  BOOLEAN            Connected;

  // one always-posted receive, drains TCP into Raw in the background
  EFI_TCP4_IO_TOKEN       RxToken;
  EFI_TCP4_RECEIVE_DATA   RxData;
  EFI_TCP4_FRAGMENT_DATA  RxFrag;  // RxData has a 1-entry table, reuse this
  UINT8                   RxScratch[RX_SCRATCH];
  BYTE_RING               Raw;

  // ssh
  WOLFSSH     *Ssh;
  WOLFSSH_CTX *Ctx;

  // input decode
  UINT8    Plain[PLAIN_SIZE];
  UINTN    PlainLen;
  KEY_RING Keys;

  // the shim protocols. embedded so we can get back to the session with BASE_CR.
  EFI_SIMPLE_TEXT_INPUT_PROTOCOL   TextIn;
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL  TextOut;
  SIMPLE_TEXT_OUTPUT_MODE          TextOutMode;
  EFI_HANDLE                       ConHandle;

  // saved console so we can put it back on exit
  EFI_SIMPLE_TEXT_INPUT_PROTOCOL  *OldConIn;
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *OldConOut;
  EFI_HANDLE                       OldConInHandle;
  EFI_HANDLE                       OldConOutHandle;
} SSH_SESSION;

#define SESSION_FROM_TEXTIN(a)  BASE_CR (a, SSH_SESSION, TextIn)
#define SESSION_FROM_TEXTOUT(a) BASE_CR (a, SSH_SESSION, TextOut)

// wolfSSH IO callbacks. Set these on the CTX. ctx pointer is the SSH_SESSION.
int SshRecvCb (WOLFSSH *ssh, void *buf, word32 sz, void *ctx);
int SshSendCb (WOLFSSH *ssh, void *buf, word32 sz, void *ctx);

// Arm (or re-arm) the persistent TCP receive. Call once after connect.
EFI_STATUS ArmReceive (SSH_SESSION *S);

// Build the shim protocols, swap gST->ConIn/ConOut to point at them.
EFI_STATUS InstallConsoleShim (SSH_SESSION *S);

// Put the real console back. Call after the nested Shell exits.
EFI_STATUS RemoveConsoleShim (SSH_SESSION *S);

// Push raw bytes to the client (helper used by the output shim).
EFI_STATUS SshSendBytes (SSH_SESSION *S, CONST UINT8 *Buf, UINTN Len);

#endif
