/** @file
  Console shim implementation. See ConsoleShim.h for the overall idea.

  Single threaded and cooperative, like everything in UEFI. Data flows like this:

    TCP  --(persistent receive + notify)-->  Raw ring
    Raw ring  --(SshRecvCb, non blocking)-->  wolfSSH
    wolfSSH  --(wolfSSH_stream_read)-->  Plain buffer  --(DecodeKeys)-->  Key ring
    Key ring  --(ShimReadKey)-->  the Shell

  and the other way for output:

    Shell  --(ShimOutputString)-->  ANSI bytes  --(wolfSSH_stream_send)-->  TCP
*/

#include "ConsoleShim.h"
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>
#include <Library/DebugLib.h>

// ---- byte ring ------------------------------------------------------------

STATIC VOID RingPut (BYTE_RING *R, UINT8 B) {
  UINTN next = (R->Head + 1) % RAW_RX_SIZE;
  if (next == R->Tail) {
    return; // full, drop. TODO: backpressure instead of dropping.
  }
  R->Data[R->Head] = B;
  R->Head = next;
}

STATIC UINTN RingGet (BYTE_RING *R, UINT8 *Out, UINTN Max) {
  UINTN n = 0;
  while (n < Max && R->Tail != R->Head) {
    Out[n++] = R->Data[R->Tail];
    R->Tail = (R->Tail + 1) % RAW_RX_SIZE;
  }
  return n;
}

// ---- key ring -------------------------------------------------------------

STATIC BOOLEAN KeyRingEmpty (SSH_SESSION *S) {
  return (BOOLEAN)(S->Keys.Head == S->Keys.Tail);
}

STATIC VOID KeyRingPut (SSH_SESSION *S, UINT16 Scan, CHAR16 Ch) {
  UINTN next = (S->Keys.Head + 1) % KEY_RING_SIZE;
  if (next == S->Keys.Tail) {
    return; // full, drop
  }
  S->Keys.Key[S->Keys.Head].ScanCode    = Scan;
  S->Keys.Key[S->Keys.Head].UnicodeChar = Ch;
  S->Keys.Head = next;
}

// ---- persistent TCP receive ----------------------------------------------

STATIC VOID EFIAPI RxNotify (EFI_EVENT Event, VOID *Context) {
  SSH_SESSION *S = (SSH_SESSION *)Context;
  UINTN       i, got;

  if (!EFI_ERROR (S->RxToken.CompletionToken.Status)) {
    got = S->RxData.FragmentTable[0].FragmentLength;
    for (i = 0; i < got; i++) {
      RingPut (&S->Raw, S->RxScratch[i]);
    }
  }
  // re-arm unless we are tearing down
  if (S->Connected) {
    ArmReceive (S);
  }
}

EFI_STATUS ArmReceive (SSH_SESSION *S) {
  EFI_STATUS Status;

  if (S->RxToken.CompletionToken.Event == NULL) {
    Status = gBS->CreateEvent (
               EVT_NOTIFY_SIGNAL, TPL_CALLBACK,
               RxNotify, S,
               &S->RxToken.CompletionToken.Event
               );
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  S->RxFrag.FragmentLength        = RX_SCRATCH;
  S->RxFrag.FragmentBuffer        = S->RxScratch;
  S->RxData.UrgentFlag            = FALSE;
  S->RxData.DataLength            = RX_SCRATCH;
  S->RxData.FragmentCount         = 1;
  S->RxData.FragmentTable[0]      = S->RxFrag;
  S->RxToken.Packet.RxData        = &S->RxData;
  S->RxToken.CompletionToken.Status = EFI_NOT_READY;

  return S->Tcp->Receive (S->Tcp, &S->RxToken);
}

// ---- wolfSSH IO callbacks -------------------------------------------------

int SshRecvCb (WOLFSSH *ssh, void *buf, word32 sz, void *ctx) {
  SSH_SESSION *S = (SSH_SESSION *)ctx;
  UINTN        n;

  (void)ssh;
  S->Tcp->Poll (S->Tcp);               // let the receive notify fire
  n = RingGet (&S->Raw, (UINT8 *)buf, sz);
  if (n == 0) {
    return WS_CBIO_ERR_WANT_READ;      // nothing yet, non blocking
  }
  return (int)n;
}

int SshSendCb (WOLFSSH *ssh, void *buf, word32 sz, void *ctx) {
  SSH_SESSION            *S = (SSH_SESSION *)ctx;
  EFI_TCP4_IO_TOKEN       tx;
  EFI_TCP4_TRANSMIT_DATA  td;
  EFI_STATUS              Status;
  UINTN                   idx;

  (void)ssh;
  ZeroMem (&tx, sizeof (tx));
  ZeroMem (&td, sizeof (td));

  Status = gBS->CreateEvent (0, TPL_CALLBACK, NULL, NULL, &tx.CompletionToken.Event);
  if (EFI_ERROR (Status)) {
    return WS_CBIO_ERR_GENERAL;
  }

  td.Push                   = TRUE;
  td.Urgent                 = FALSE;
  td.DataLength             = sz;
  td.FragmentCount          = 1;
  td.FragmentTable[0].FragmentLength = sz;
  td.FragmentTable[0].FragmentBuffer = buf;
  tx.Packet.TxData          = &td;
  tx.CompletionToken.Status = EFI_NOT_READY;

  Status = S->Tcp->Transmit (S->Tcp, &tx);
  if (!EFI_ERROR (Status)) {
    gBS->WaitForEvent (1, &tx.CompletionToken.Event, &idx);
    Status = tx.CompletionToken.Status;
  }
  gBS->CloseEvent (tx.CompletionToken.Event);

  if (EFI_ERROR (Status)) {
    return WS_CBIO_ERR_GENERAL;
  }
  return (int)sz;
}

EFI_STATUS SshSendBytes (SSH_SESSION *S, CONST UINT8 *Buf, UINTN Len) {
  int sent = wolfSSH_stream_send (S->Ssh, (byte *)Buf, (word32)Len);
  return (sent > 0) ? EFI_SUCCESS : EFI_DEVICE_ERROR;
}

// ---- input: turn a byte stream into EFI keys ------------------------------
//
// Handles the common stuff: CR, backspace, tab, printable ASCII, and the
// arrow / delete escape sequences. Function keys, Home/End/PgUp/PgDn and
// UTF-8 multibyte input are left as TODO. The escape parser here is minimal,
// it does not deal with a lone ESC that is not followed by more bytes yet.

STATIC VOID DecodeKeys (SSH_SESSION *S) {
  UINTN i = 0;

  while (i < S->PlainLen) {
    UINT8 c = S->Plain[i];

    if (c == 0x1b && (i + 2) < S->PlainLen && S->Plain[i + 1] == '[') {
      UINT8 f = S->Plain[i + 2];
      switch (f) {
        case 'A': KeyRingPut (S, SCAN_UP, 0);    i += 3; continue;
        case 'B': KeyRingPut (S, SCAN_DOWN, 0);  i += 3; continue;
        case 'C': KeyRingPut (S, SCAN_RIGHT, 0); i += 3; continue;
        case 'D': KeyRingPut (S, SCAN_LEFT, 0);  i += 3; continue;
        case '3':
          if ((i + 3) < S->PlainLen && S->Plain[i + 3] == '~') {
            KeyRingPut (S, SCAN_DELETE, 0);
            i += 4;
            continue;
          }
          break;
        // TODO: 1~ Home, 4~ End, 5~ PgUp, 6~ PgDn, ESC O P.. for F1..F4
        default:
          break;
      }
      // unknown escape, drop the ESC and let the rest fall through
      i += 1;
      continue;
    }

    if (c == 0x1b && (i + 1) == S->PlainLen) {
      break; // incomplete escape, wait for more bytes next pump
    }

    if (c == 0x0d || c == 0x0a) {
      KeyRingPut (S, SCAN_NULL, CHAR_CARRIAGE_RETURN);
      i += 1;
      // swallow a following LF so CRLF is one Enter
      if (i < S->PlainLen && S->Plain[i] == 0x0a) i += 1;
      continue;
    }
    if (c == 0x7f || c == 0x08) {
      KeyRingPut (S, SCAN_NULL, CHAR_BACKSPACE);
      i += 1;
      continue;
    }
    if (c == 0x1b) {
      KeyRingPut (S, SCAN_ESC, 0);
      i += 1;
      continue;
    }
    // printable and other control chars (ctrl-c etc) pass through as-is
    KeyRingPut (S, SCAN_NULL, (CHAR16)c);
    i += 1;
  }

  // shift any leftover (incomplete escape) to the front
  if (i > 0 && i < S->PlainLen) {
    CopyMem (S->Plain, S->Plain + i, S->PlainLen - i);
  }
  S->PlainLen -= i;
}

STATIC VOID PumpInput (SSH_SESSION *S) {
  int n;
  S->Tcp->Poll (S->Tcp);
  n = wolfSSH_stream_read (S->Ssh, S->Plain + S->PlainLen,
                           (word32)(PLAIN_SIZE - S->PlainLen));
  if (n > 0) {
    S->PlainLen += (UINTN)n;
    DecodeKeys (S);
  }
  // n <= 0 usually means WS_WANT_READ, nothing to do
}

// ---- SimpleTextIn shim ----------------------------------------------------

STATIC EFI_STATUS EFIAPI ShimInReset (
  EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This, BOOLEAN Extended
  ) {
  SSH_SESSION *S = SESSION_FROM_TEXTIN (This);
  (void)Extended;
  S->Keys.Head = S->Keys.Tail = 0;
  S->PlainLen  = 0;
  return EFI_SUCCESS;
}

STATIC EFI_STATUS EFIAPI ShimReadKey (
  EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This, EFI_INPUT_KEY *Key
  ) {
  SSH_SESSION *S = SESSION_FROM_TEXTIN (This);
  PumpInput (S);
  if (KeyRingEmpty (S)) {
    return EFI_NOT_READY;
  }
  *Key = S->Keys.Key[S->Keys.Tail];
  S->Keys.Tail = (S->Keys.Tail + 1) % KEY_RING_SIZE;
  return EFI_SUCCESS;
}

STATIC VOID EFIAPI WaitKeyNotify (EFI_EVENT Event, VOID *Context) {
  SSH_SESSION *S = (SSH_SESSION *)Context;
  PumpInput (S);
  if (!KeyRingEmpty (S)) {
    gBS->SignalEvent (S->TextIn.WaitForKey);
  }
}

// ---- SimpleTextOut shim ---------------------------------------------------

STATIC EFI_STATUS SendAscii (SSH_SESSION *S, CONST CHAR8 *Str) {
  return SshSendBytes (S, (CONST UINT8 *)Str, AsciiStrLen (Str));
}

STATIC EFI_STATUS EFIAPI ShimOutReset (
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, BOOLEAN Extended
  ) {
  SSH_SESSION *S = SESSION_FROM_TEXTOUT (This);
  (void)Extended;
  return SendAscii (S, "\x1b[2J\x1b[H");
}

STATIC EFI_STATUS EFIAPI ShimOutputString (
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, CHAR16 *String
  ) {
  SSH_SESSION *S = SESSION_FROM_TEXTOUT (This);
  UINT8       out[256];
  UINTN       n = 0;

  while (*String) {
    CHAR16 c = *String++;
    if (n > sizeof (out) - 3) {
      SshSendBytes (S, out, n);
      n = 0;
    }
    if (c == L'\n') {
      out[n++] = '\r';
      out[n++] = '\n';
    } else if (c < 0x80) {
      out[n++] = (UINT8)c;
    } else {
      out[n++] = '?';   // TODO: proper UTF-8 encode of the CHAR16
    }
  }
  if (n) {
    SshSendBytes (S, out, n);
  }
  return EFI_SUCCESS;
}

STATIC EFI_STATUS EFIAPI ShimTestString (
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, CHAR16 *String
  ) {
  (void)This; (void)String;
  return EFI_SUCCESS; // claim we can render anything
}

STATIC EFI_STATUS EFIAPI ShimQueryMode (
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, UINTN Mode, UINTN *Cols, UINTN *Rows
  ) {
  (void)This;
  if (Mode != 0) {
    return EFI_UNSUPPORTED;
  }
  *Cols = 80;   // TODO: read the real size from the pty-req window if you want
  *Rows = 25;
  return EFI_SUCCESS;
}

STATIC EFI_STATUS EFIAPI ShimSetMode (
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, UINTN Mode
  ) {
  SSH_SESSION *S = SESSION_FROM_TEXTOUT (This);
  if (Mode != 0) {
    return EFI_UNSUPPORTED;
  }
  S->TextOutMode.Mode = 0;
  return SendAscii (S, "\x1b[2J\x1b[H");
}

STATIC EFI_STATUS EFIAPI ShimSetAttribute (
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, UINTN Attribute
  ) {
  SSH_SESSION *S = SESSION_FROM_TEXTOUT (This);
  // EFI colour order differs from ANSI, remap it
  STATIC CONST UINT8 efiToAnsi[8] = { 0, 4, 2, 6, 1, 5, 3, 7 };
  UINTN fg = Attribute & 0x07;
  UINTN bg = (Attribute >> 4) & 0x07;
  UINTN bright = (Attribute & 0x08) ? 1 : 0;
  CHAR8 buf[32];

  S->TextOutMode.Attribute = (INT32)Attribute;
  AsciiSPrint (buf, sizeof (buf), "\x1b[0;%d;%dm",
               (bright ? 90 : 30) + efiToAnsi[fg],
               40 + efiToAnsi[bg]);
  return SendAscii (S, buf);
}

STATIC EFI_STATUS EFIAPI ShimClearScreen (
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This
  ) {
  SSH_SESSION *S = SESSION_FROM_TEXTOUT (This);
  S->TextOutMode.CursorColumn = 0;
  S->TextOutMode.CursorRow    = 0;
  return SendAscii (S, "\x1b[2J\x1b[H");
}

STATIC EFI_STATUS EFIAPI ShimSetCursor (
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, UINTN Col, UINTN Row
  ) {
  SSH_SESSION *S = SESSION_FROM_TEXTOUT (This);
  CHAR8 buf[32];
  S->TextOutMode.CursorColumn = (INT32)Col;
  S->TextOutMode.CursorRow    = (INT32)Row;
  AsciiSPrint (buf, sizeof (buf), "\x1b[%d;%dH", (int)Row + 1, (int)Col + 1);
  return SendAscii (S, buf);
}

STATIC EFI_STATUS EFIAPI ShimEnableCursor (
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, BOOLEAN Visible
  ) {
  SSH_SESSION *S = SESSION_FROM_TEXTOUT (This);
  S->TextOutMode.CursorVisible = Visible;
  return SendAscii (S, Visible ? "\x1b[?25h" : "\x1b[?25l");
}

// ---- install / remove -----------------------------------------------------

EFI_STATUS InstallConsoleShim (SSH_SESSION *S) {
  EFI_STATUS Status;

  // input
  S->TextIn.Reset         = ShimInReset;
  S->TextIn.ReadKeyStroke = ShimReadKey;
  Status = gBS->CreateEvent (
             EVT_NOTIFY_WAIT, TPL_NOTIFY,
             WaitKeyNotify, S,
             &S->TextIn.WaitForKey
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  // output
  S->TextOutMode.MaxMode       = 1;
  S->TextOutMode.Mode          = 0;
  S->TextOutMode.Attribute     = 0x07;
  S->TextOutMode.CursorColumn  = 0;
  S->TextOutMode.CursorRow     = 0;
  S->TextOutMode.CursorVisible = TRUE;

  S->TextOut.Reset             = ShimOutReset;
  S->TextOut.OutputString      = ShimOutputString;
  S->TextOut.TestString        = ShimTestString;
  S->TextOut.QueryMode         = ShimQueryMode;
  S->TextOut.SetMode           = ShimSetMode;
  S->TextOut.SetAttribute      = ShimSetAttribute;
  S->TextOut.ClearScreen       = ShimClearScreen;
  S->TextOut.SetCursorPosition = ShimSetCursor;
  S->TextOut.EnableCursor      = ShimEnableCursor;
  S->TextOut.Mode              = &S->TextOutMode;

  // install both on a fresh handle so ConsoleInHandle/OutHandle have something
  // real to point at (some Shell code queries the handle, not just the pointer)
  S->ConHandle = NULL;
  Status = gBS->InstallMultipleProtocolInterfaces (
             &S->ConHandle,
             &gEfiSimpleTextInProtocolGuid,  &S->TextIn,
             &gEfiSimpleTextOutProtocolGuid, &S->TextOut,
             NULL
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  // save the current console then swap in ours
  S->OldConIn         = gST->ConIn;
  S->OldConOut        = gST->ConOut;
  S->OldConInHandle   = gST->ConsoleInHandle;
  S->OldConOutHandle  = gST->ConsoleOutHandle;

  gST->ConIn            = &S->TextIn;
  gST->ConOut           = &S->TextOut;
  gST->StdErr           = &S->TextOut;
  gST->ConsoleInHandle  = S->ConHandle;
  gST->ConsoleOutHandle = S->ConHandle;
  gST->StandardErrorHandle = S->ConHandle;

  // the system table has a CRC in its header, fix it or later checks fail
  gST->Hdr.CRC32 = 0;
  gBS->CalculateCrc32 (gST, gST->Hdr.HeaderSize, &gST->Hdr.CRC32);

  return EFI_SUCCESS;
}

EFI_STATUS RemoveConsoleShim (SSH_SESSION *S) {
  gST->ConIn            = S->OldConIn;
  gST->ConOut           = S->OldConOut;
  gST->StdErr           = S->OldConOut;
  gST->ConsoleInHandle  = S->OldConInHandle;
  gST->ConsoleOutHandle = S->OldConOutHandle;
  gST->StandardErrorHandle = S->OldConOutHandle;

  gST->Hdr.CRC32 = 0;
  gBS->CalculateCrc32 (gST, gST->Hdr.HeaderSize, &gST->Hdr.CRC32);

  if (S->TextIn.WaitForKey) {
    gBS->CloseEvent (S->TextIn.WaitForKey);
  }
  if (S->ConHandle) {
    gBS->UninstallMultipleProtocolInterfaces (
      S->ConHandle,
      &gEfiSimpleTextInProtocolGuid,  &S->TextIn,
      &gEfiSimpleTextOutProtocolGuid, &S->TextOut,
      NULL
      );
  }
  return EFI_SUCCESS;
}
