/* Console shim implementation. See ConsoleShim.h for the idea.

   Input:  SSH channel bytes go through a small escape sequence and UTF-8 decoder into a ring of EFI_KEY_DATA that ReadKeyStroke hands to the Shell.
   Output: CHAR16 strings from the Shell become UTF-8 plus a few ANSI escapes and go out through SshWrite. The cursor position is modelled the way xterm behaves, since the Shell's line editor trusts Mode->CursorColumn and CursorRow.

   If the client disconnects while the Shell is running, the shim types "exit" for the Shell and also falls back to the real local console so the machine is never left without a keyboard. */

#include "ConsoleShim.h"
#include "uefirt.h"
#include <string.h>

#define ESC_TIMEOUT_TICKS 300000000ULL
#define SHIM_EXIT_INJECT_MAX 40

#define SHIM_FROM_IN(This)   ((CONSOLE_SHIM *)((UINT8 *)(This) - offsetof(CONSOLE_SHIM, TextIn)))
#define SHIM_FROM_INEX(This) ((CONSOLE_SHIM *)((UINT8 *)(This) - offsetof(CONSOLE_SHIM, TextInEx)))
#define SHIM_FROM_OUT(This)  ((CONSOLE_SHIM *)((UINT8 *)(This) - offsetof(CONSOLE_SHIM, TextOut)))

/* Output side */

static void Flush(CONSOLE_SHIM *S)
{
    if (S->OutLen == 0) {
        return;
    }
    if (!S->Disconnected) {
        if (SshWrite(S->Ssh, S->OutBuf, S->OutLen) != 0) {
            S->Disconnected = TRUE;
        }
    }
    if (S->Disconnected && S->OldConOut != NULL) {
        /* Mirror to the real screen so whoever is at the machine can see what the stuck Shell is doing. */
        CHAR16 tmp[128];
        UINTN  i, n = 0;
        for (i = 0; i < S->OutLen; i++) {
            UINT8 b = S->OutBuf[i];
            if (b >= 0x20 && b < 0x7f) {
                tmp[n++] = b;
            } else if (b == '\n') {
                tmp[n++] = '\r';
                tmp[n++] = '\n';
            }
            if (n >= 120) {
                tmp[n] = 0;
                S->OldConOut->OutputString(S->OldConOut, tmp);
                n = 0;
            }
        }
        tmp[n] = 0;
        if (n > 0) {
            S->OldConOut->OutputString(S->OldConOut, tmp);
        }
    }
    S->OutLen = 0;
}

static void EmitByte(CONSOLE_SHIM *S, UINT8 b)
{
    if (S->OutLen >= SHIM_OUT_BUF) {
        Flush(S);
    }
    S->OutBuf[S->OutLen++] = b;
}

static void Emit(CONSOLE_SHIM *S, const char *s)
{
    while (*s != 0) {
        EmitByte(S, (UINT8)*s++);
    }
}

static void EmitNum(CONSOLE_SHIM *S, UINTN v)
{
    char tmp[12];
    int  n = 0;
    do {
        tmp[n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v != 0);
    while (n > 0) {
        EmitByte(S, (UINT8)tmp[--n]);
    }
}

static void EmitUtf8(CONSOLE_SHIM *S, CHAR16 c)
{
    if (c < 0x80) {
        EmitByte(S, (UINT8)c);
    } else if (c < 0x800) {
        EmitByte(S, (UINT8)(0xC0 | (c >> 6)));
        EmitByte(S, (UINT8)(0x80 | (c & 0x3F)));
    } else {
        EmitByte(S, (UINT8)(0xE0 | (c >> 12)));
        EmitByte(S, (UINT8)(0x80 | ((c >> 6) & 0x3F)));
        EmitByte(S, (UINT8)(0x80 | (c & 0x3F)));
    }
}

static void RefreshSize(CONSOLE_SHIM *S)
{
    UINT32 c, r;
    SshGetWindow(S->Ssh, &c, &r);
    S->Cols = (c >= 20) ? c : 80;
    S->Rows = (r >= 5) ? r : 25;
}

static void RowDown(CONSOLE_SHIM *S)
{
    if ((UINT32)S->Mode.CursorRow + 1 < S->Rows) {
        S->Mode.CursorRow++;
    }
}

static EFI_STATUS EFIAPI ShimOutputString(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, CHAR16 *String)
{
    CONSOLE_SHIM *S = SHIM_FROM_OUT(This);

    if ((++S->OutPoll & 15) == 0 && !S->Disconnected) {
        if (SshPoll(S->Ssh) < 0) {
            S->Disconnected = TRUE;
        }
    }
    while (*String != 0) {
        CHAR16 c = *String++;
        switch (c) {
        case CHAR_LINEFEED:
            EmitByte(S, '\r');
            EmitByte(S, '\n');
            S->Mode.CursorColumn = 0;
            S->PendingWrap = FALSE;
            RowDown(S);
            break;
        case CHAR_CARRIAGE_RETURN:
            EmitByte(S, '\r');
            S->Mode.CursorColumn = 0;
            S->PendingWrap = FALSE;
            break;
        case CHAR_BACKSPACE:
            if (S->Mode.CursorColumn > 0) {
                S->Mode.CursorColumn--;
                EmitByte(S, 0x08);
            }
            S->PendingWrap = FALSE;
            break;
        case CHAR_TAB:
            EmitByte(S, '\t');
            S->Mode.CursorColumn = (S->Mode.CursorColumn & ~7) + 8;
            if ((UINT32)S->Mode.CursorColumn >= S->Cols) {
                S->Mode.CursorColumn = (INT32)S->Cols - 1;
            }
            S->PendingWrap = FALSE;
            break;
        default:
            if (c < 0x20) {
                EmitByte(S, (UINT8)c);
                break;
            }
            if (S->PendingWrap) {
                S->Mode.CursorColumn = 0;
                RowDown(S);
                S->PendingWrap = FALSE;
            }
            EmitUtf8(S, c);
            if ((UINT32)S->Mode.CursorColumn + 1 >= S->Cols) {
                S->Mode.CursorColumn = (INT32)S->Cols - 1;
                S->PendingWrap = TRUE;
            } else {
                S->Mode.CursorColumn++;
            }
            break;
        }
    }
    Flush(S);
    return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI ShimTestString(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, CHAR16 *String)
{
    (void)This;
    (void)String;
    return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI ShimQueryMode(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, UINTN ModeNumber, UINTN *Columns, UINTN *Rows)
{
    CONSOLE_SHIM *S = SHIM_FROM_OUT(This);
    if (ModeNumber != 0) {
        return EFI_UNSUPPORTED;
    }
    RefreshSize(S);
    *Columns = S->Cols;
    *Rows = S->Rows;
    return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI ShimClearScreen(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This)
{
    CONSOLE_SHIM *S = SHIM_FROM_OUT(This);
    Emit(S, "\x1b[2J\x1b[H");
    S->Mode.CursorColumn = 0;
    S->Mode.CursorRow = 0;
    S->PendingWrap = FALSE;
    Flush(S);
    return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI ShimSetMode(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, UINTN ModeNumber)
{
    CONSOLE_SHIM *S = SHIM_FROM_OUT(This);
    if (ModeNumber != 0) {
        return EFI_UNSUPPORTED;
    }
    S->Mode.Mode = 0;
    RefreshSize(S);
    return ShimClearScreen(This);
}

static EFI_STATUS EFIAPI ShimSetAttribute(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, UINTN Attribute)
{
    CONSOLE_SHIM *S = SHIM_FROM_OUT(This);
    static const UINT8 efiToAnsi[8] = { 0, 4, 2, 6, 1, 5, 3, 7 };
    UINTN fg = Attribute & 0x07;
    UINTN bg = (Attribute >> 4) & 0x07;
    BOOLEAN bright = (Attribute & 0x08) != 0;

    if (Attribute > 0x7F) {
        return EFI_UNSUPPORTED;
    }
    S->Mode.Attribute = (INT32)Attribute;
    Emit(S, "\x1b[0;");
    EmitNum(S, (bright ? 90 : 30) + efiToAnsi[fg]);
    EmitByte(S, ';');
    EmitNum(S, 40 + efiToAnsi[bg]);
    EmitByte(S, 'm');
    Flush(S);
    return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI ShimSetCursor(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, UINTN Column, UINTN Row)
{
    CONSOLE_SHIM *S = SHIM_FROM_OUT(This);
    if (Column >= S->Cols || Row >= S->Rows) {
        return EFI_UNSUPPORTED;
    }
    S->Mode.CursorColumn = (INT32)Column;
    S->Mode.CursorRow = (INT32)Row;
    S->PendingWrap = FALSE;
    Emit(S, "\x1b[");
    EmitNum(S, Row + 1);
    EmitByte(S, ';');
    EmitNum(S, Column + 1);
    EmitByte(S, 'H');
    Flush(S);
    return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI ShimEnableCursor(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, BOOLEAN Visible)
{
    CONSOLE_SHIM *S = SHIM_FROM_OUT(This);
    S->Mode.CursorVisible = Visible;
    Emit(S, Visible ? "\x1b[?25h" : "\x1b[?25l");
    Flush(S);
    return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI ShimOutReset(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, BOOLEAN ExtendedVerification)
{
    CONSOLE_SHIM *S = SHIM_FROM_OUT(This);
    (void)ExtendedVerification;
    S->Mode.Attribute = 0x07;
    S->Mode.CursorVisible = TRUE;
    Emit(S, "\x1b[0m\x1b[?25h");
    Flush(S);
    return ShimClearScreen(This);
}

/* Input side */

static BOOLEAN KeysEmpty(CONSOLE_SHIM *S)
{
    return (BOOLEAN)(S->KeyHead == S->KeyTail);
}

static BOOLEAN NotifyMatches(const EFI_KEY_DATA *reg, const EFI_KEY_DATA *kd)
{
    if (reg->Key.ScanCode != kd->Key.ScanCode || reg->Key.UnicodeChar != kd->Key.UnicodeChar) {
        return FALSE;
    }
    if ((reg->KeyState.KeyShiftState & EFI_SHIFT_STATE_VALID) != 0) {
        if ((reg->KeyState.KeyShiftState & ~EFI_SHIFT_STATE_VALID) != (kd->KeyState.KeyShiftState & ~EFI_SHIFT_STATE_VALID)) {
            return FALSE;
        }
    }
    return TRUE;
}

static void FireNotify(CONSOLE_SHIM *S, EFI_KEY_DATA *kd)
{
    UINTN i;
    for (i = 0; i < SHIM_MAX_NOTIFY; i++) {
        if (S->Notify[i].Used && S->Notify[i].Fn != NULL && NotifyMatches(&S->Notify[i].Key, kd)) {
            S->Notify[i].Fn(kd);
        }
    }
}

static void PushKeyData(CONSOLE_SHIM *S, EFI_KEY_DATA *kd)
{
    UINTN next = (S->KeyHead + 1) % SHIM_KEY_RING;
    FireNotify(S, kd);
    if (next == S->KeyTail) {
        return;
    }
    S->Keys[S->KeyHead] = *kd;
    S->KeyHead = next;
}

static void PushKey(CONSOLE_SHIM *S, UINT16 scan, CHAR16 ch)
{
    EFI_KEY_DATA kd;
    memset(&kd, 0, sizeof(kd));
    kd.Key.ScanCode = scan;
    kd.Key.UnicodeChar = ch;
    kd.KeyState.KeyShiftState = EFI_SHIFT_STATE_VALID;
    if (scan == SCAN_NULL && ch >= 1 && ch <= 26 && ch != CHAR_BACKSPACE && ch != CHAR_TAB && ch != CHAR_LINEFEED && ch != CHAR_CARRIAGE_RETURN) {
        /* Control character. Registered notifies may use either the letter form or the control code form, so fire the letter form too. */
        EFI_KEY_DATA alt = kd;
        kd.KeyState.KeyShiftState |= EFI_LEFT_CONTROL_PRESSED;
        alt.KeyState.KeyShiftState |= EFI_LEFT_CONTROL_PRESSED;
        alt.Key.UnicodeChar = (CHAR16)('a' + ch - 1);
        FireNotify(S, &alt);
    }
    PushKeyData(S, &kd);
}

/* Sends a Ctrl-C through the notify path only, used when the client vanishes so a running command gets a break. */
static void FireBreak(CONSOLE_SHIM *S)
{
    EFI_KEY_DATA kd;
    memset(&kd, 0, sizeof(kd));
    kd.Key.UnicodeChar = 3;
    kd.KeyState.KeyShiftState = EFI_SHIFT_STATE_VALID | EFI_LEFT_CONTROL_PRESSED;
    FireNotify(S, &kd);
    kd.Key.UnicodeChar = 'c';
    FireNotify(S, &kd);
}

static void InjectExit(CONSOLE_SHIM *S)
{
    const char *cmd = "exit";
    if (!KeysEmpty(S) || S->ExitInjects >= SHIM_EXIT_INJECT_MAX) {
        return;
    }
    S->ExitInjects++;
    while (*cmd != 0) {
        PushKey(S, SCAN_NULL, (CHAR16)*cmd++);
    }
    PushKey(S, SCAN_NULL, CHAR_CARRIAGE_RETURN);
}

static void HandleCsi(CONSOLE_SHIM *S)
{
    UINT8  final = S->Esc[S->EscLen - 1];
    UINTN  num = 0;
    UINTN  i;
    UINT16 scan = SCAN_NULL;

    for (i = 2; i < S->EscLen - 1 && S->Esc[i] >= '0' && S->Esc[i] <= '9'; i++) {
        num = num * 10 + (S->Esc[i] - '0');
    }
    switch (final) {
    case 'A': scan = SCAN_UP; break;
    case 'B': scan = SCAN_DOWN; break;
    case 'C': scan = SCAN_RIGHT; break;
    case 'D': scan = SCAN_LEFT; break;
    case 'H': scan = SCAN_HOME; break;
    case 'F': scan = SCAN_END; break;
    case 'P': scan = SCAN_F1; break;
    case 'Q': scan = SCAN_F2; break;
    case 'R': scan = SCAN_F3; break;
    case 'S': scan = SCAN_F4; break;
    case '~':
        switch (num) {
        case 1: scan = SCAN_HOME; break;
        case 2: scan = SCAN_INSERT; break;
        case 3: scan = SCAN_DELETE; break;
        case 4: scan = SCAN_END; break;
        case 5: scan = SCAN_PAGE_UP; break;
        case 6: scan = SCAN_PAGE_DOWN; break;
        case 7: scan = SCAN_HOME; break;
        case 8: scan = SCAN_END; break;
        case 11: scan = SCAN_F1; break;
        case 12: scan = SCAN_F2; break;
        case 13: scan = SCAN_F3; break;
        case 14: scan = SCAN_F4; break;
        case 15: scan = SCAN_F5; break;
        case 17: scan = SCAN_F6; break;
        case 18: scan = SCAN_F7; break;
        case 19: scan = SCAN_F8; break;
        case 20: scan = SCAN_F9; break;
        case 21: scan = SCAN_F10; break;
        case 23: scan = SCAN_F11; break;
        case 24: scan = SCAN_F12; break;
        default: break;
        }
        break;
    default:
        break;
    }
    if (scan != SCAN_NULL) {
        PushKey(S, scan, 0);
    }
}

static void HandleSs3(CONSOLE_SHIM *S, UINT8 b)
{
    UINT16 scan = SCAN_NULL;
    switch (b) {
    case 'A': scan = SCAN_UP; break;
    case 'B': scan = SCAN_DOWN; break;
    case 'C': scan = SCAN_RIGHT; break;
    case 'D': scan = SCAN_LEFT; break;
    case 'H': scan = SCAN_HOME; break;
    case 'F': scan = SCAN_END; break;
    case 'P': scan = SCAN_F1; break;
    case 'Q': scan = SCAN_F2; break;
    case 'R': scan = SCAN_F3; break;
    case 'S': scan = SCAN_F4; break;
    default: break;
    }
    if (scan != SCAN_NULL) {
        PushKey(S, scan, 0);
    }
}

static void FeedByte(CONSOLE_SHIM *S, UINT8 b);

/* An escape that never completed: deliver ESC itself and replay the rest as plain bytes. */
static void FlushEsc(CONSOLE_SHIM *S)
{
    UINT8 saved[24];
    UINTN n = S->EscLen;
    UINTN i;
    memcpy(saved, S->Esc, n);
    S->EscLen = 0;
    PushKey(S, SCAN_ESC, 0);
    for (i = 1; i < n; i++) {
        FeedByte(S, saved[i]);
    }
}

static void FeedByte(CONSOLE_SHIM *S, UINT8 b)
{
    if (S->EscLen > 0) {
        if (S->EscLen < sizeof(S->Esc)) {
            S->Esc[S->EscLen++] = b;
        }
        if (S->EscLen == 2) {
            if (b == '[' || b == 'O') {
                return;
            }
            S->EscLen = 0;
            PushKey(S, SCAN_ESC, 0);
            FeedByte(S, b);
            return;
        }
        if (S->Esc[1] == 'O') {
            S->EscLen = 0;
            HandleSs3(S, b);
            return;
        }
        if (b >= 0x40 && b <= 0x7E) {
            HandleCsi(S);
            S->EscLen = 0;
            return;
        }
        if (S->EscLen >= sizeof(S->Esc)) {
            S->EscLen = 0;
        }
        return;
    }
    if (b == 0x1b) {
        S->Esc[0] = b;
        S->EscLen = 1;
        S->EscTick = RtTicks();
        return;
    }
    if (S->Utf8Need > 0) {
        if ((b & 0xC0) == 0x80) {
            S->Utf8Acc = (S->Utf8Acc << 6) | (b & 0x3F);
            if (--S->Utf8Need == 0 && S->Utf8Acc <= 0xFFFF) {
                PushKey(S, SCAN_NULL, (CHAR16)S->Utf8Acc);
            }
            return;
        }
        S->Utf8Need = 0;
    }
    if (b >= 0xF0) {
        S->Utf8Acc = b & 0x07;
        S->Utf8Need = 3;
        return;
    }
    if (b >= 0xE0) {
        S->Utf8Acc = b & 0x0F;
        S->Utf8Need = 2;
        return;
    }
    if (b >= 0xC0) {
        S->Utf8Acc = b & 0x1F;
        S->Utf8Need = 1;
        return;
    }
    if (b == '\r') {
        S->LastWasCr = TRUE;
        PushKey(S, SCAN_NULL, CHAR_CARRIAGE_RETURN);
        return;
    }
    if (b == '\n') {
        if (S->LastWasCr) {
            S->LastWasCr = FALSE;
            return;
        }
        PushKey(S, SCAN_NULL, CHAR_CARRIAGE_RETURN);
        return;
    }
    S->LastWasCr = FALSE;
    if (b == 0x7f || b == 0x08) {
        PushKey(S, SCAN_NULL, CHAR_BACKSPACE);
        return;
    }
    PushKey(S, SCAN_NULL, (CHAR16)b);
}

static void PumpInput(CONSOLE_SHIM *S)
{
    UINT8 buf[256];
    int   n;

    if (S->Disconnected) {
        InjectExit(S);
        return;
    }
    for (;;) {
        n = SshRead(S->Ssh, buf, sizeof(buf));
        if (n < 0) {
            S->Disconnected = TRUE;
            Print("Client gone, asking the Shell to exit. Local keyboard is live again.\n");
            FireBreak(S);
            InjectExit(S);
            return;
        }
        if (n == 0) {
            break;
        }
        {
            int i;
            for (i = 0; i < n; i++) {
                FeedByte(S, buf[i]);
            }
        }
        if (n < (int)sizeof(buf)) {
            break;
        }
    }
    if (S->EscLen > 0 && RtTicks() - S->EscTick > ESC_TIMEOUT_TICKS) {
        FlushEsc(S);
    }
}

static BOOLEAN PopKey(CONSOLE_SHIM *S, EFI_KEY_DATA *kd)
{
    if (KeysEmpty(S)) {
        return FALSE;
    }
    *kd = S->Keys[S->KeyTail];
    S->KeyTail = (S->KeyTail + 1) % SHIM_KEY_RING;
    return TRUE;
}

static EFI_STATUS ReadCommon(CONSOLE_SHIM *S, EFI_KEY_DATA *kd)
{
    PumpInput(S);
    if (PopKey(S, kd)) {
        return EFI_SUCCESS;
    }
    if (S->Disconnected && S->OldConIn != NULL) {
        memset(kd, 0, sizeof(*kd));
        return S->OldConIn->ReadKeyStroke(S->OldConIn, &kd->Key);
    }
    return EFI_NOT_READY;
}

static EFI_STATUS EFIAPI ShimInReset(EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This, BOOLEAN ExtendedVerification)
{
    CONSOLE_SHIM *S = SHIM_FROM_IN(This);
    (void)ExtendedVerification;
    S->KeyHead = S->KeyTail = 0;
    S->EscLen = 0;
    S->Utf8Need = 0;
    return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI ShimReadKey(EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This, EFI_INPUT_KEY *Key)
{
    CONSOLE_SHIM *S = SHIM_FROM_IN(This);
    EFI_KEY_DATA  kd;
    EFI_STATUS    st = ReadCommon(S, &kd);
    if (!EFI_ERROR(st)) {
        *Key = kd.Key;
    }
    return st;
}

static EFI_STATUS EFIAPI ShimInResetEx(EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This, BOOLEAN ExtendedVerification)
{
    CONSOLE_SHIM *S = SHIM_FROM_INEX(This);
    return ShimInReset(&S->TextIn, ExtendedVerification);
}

static EFI_STATUS EFIAPI ShimReadKeyEx(EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This, EFI_KEY_DATA *KeyData)
{
    CONSOLE_SHIM *S = SHIM_FROM_INEX(This);
    if (KeyData == NULL) {
        return EFI_INVALID_PARAMETER;
    }
    return ReadCommon(S, KeyData);
}

static EFI_STATUS EFIAPI ShimSetState(EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This, EFI_KEY_TOGGLE_STATE *KeyToggleState)
{
    (void)This;
    (void)KeyToggleState;
    return EFI_UNSUPPORTED;
}

static EFI_STATUS EFIAPI ShimRegisterNotify(EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This, EFI_KEY_DATA *KeyData, EFI_KEY_NOTIFY_FUNCTION Fn, VOID **NotifyHandle)
{
    CONSOLE_SHIM *S = SHIM_FROM_INEX(This);
    UINTN i;
    if (KeyData == NULL || Fn == NULL || NotifyHandle == NULL) {
        return EFI_INVALID_PARAMETER;
    }
    for (i = 0; i < SHIM_MAX_NOTIFY; i++) {
        if (!S->Notify[i].Used) {
            S->Notify[i].Used = TRUE;
            S->Notify[i].Key = *KeyData;
            S->Notify[i].Fn = Fn;
            *NotifyHandle = &S->Notify[i];
            return EFI_SUCCESS;
        }
    }
    return EFI_OUT_OF_RESOURCES;
}

static EFI_STATUS EFIAPI ShimUnregisterNotify(EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This, VOID *NotifyHandle)
{
    CONSOLE_SHIM *S = SHIM_FROM_INEX(This);
    UINTN i;
    for (i = 0; i < SHIM_MAX_NOTIFY; i++) {
        if (NotifyHandle == &S->Notify[i] && S->Notify[i].Used) {
            S->Notify[i].Used = FALSE;
            S->Notify[i].Fn = NULL;
            return EFI_SUCCESS;
        }
    }
    return EFI_INVALID_PARAMETER;
}

static VOID EFIAPI ShimWaitKeyNotify(EFI_EVENT Event, VOID *Context)
{
    CONSOLE_SHIM *S = Context;
    PumpInput(S);
    if (!KeysEmpty(S)) {
        gBS->SignalEvent(Event);
        return;
    }
    if (S->Disconnected && S->OldConIn != NULL && S->OldConIn->WaitForKey != NULL) {
        if (gBS->CheckEvent(S->OldConIn->WaitForKey) == EFI_SUCCESS) {
            gBS->SignalEvent(Event);
        }
    }
}

/* Install and remove */

static void FixCrc(void)
{
    UINT32 crc = 0;
    gST->Hdr.CRC32 = 0;
    gBS->CalculateCrc32(gST, gST->Hdr.HeaderSize, &crc);
    gST->Hdr.CRC32 = crc;
}

EFI_STATUS ShimInstall(CONSOLE_SHIM *S, SSH_CONN *ssh)
{
    EFI_STATUS st;

    memset(S, 0, sizeof(*S));
    S->Ssh = ssh;
    RefreshSize(S);

    S->TextIn.Reset = ShimInReset;
    S->TextIn.ReadKeyStroke = ShimReadKey;
    st = gBS->CreateEvent(EVT_NOTIFY_WAIT, TPL_CALLBACK, ShimWaitKeyNotify, S, &S->TextIn.WaitForKey);
    if (EFI_ERROR(st)) {
        return st;
    }
    S->TextInEx.Reset = ShimInResetEx;
    S->TextInEx.ReadKeyStrokeEx = ShimReadKeyEx;
    S->TextInEx.SetState = ShimSetState;
    S->TextInEx.RegisterKeyNotify = ShimRegisterNotify;
    S->TextInEx.UnregisterKeyNotify = ShimUnregisterNotify;
    st = gBS->CreateEvent(EVT_NOTIFY_WAIT, TPL_CALLBACK, ShimWaitKeyNotify, S, &S->TextInEx.WaitForKeyEx);
    if (EFI_ERROR(st)) {
        gBS->CloseEvent(S->TextIn.WaitForKey);
        return st;
    }

    S->Mode.MaxMode = 1;
    S->Mode.Mode = 0;
    S->Mode.Attribute = 0x07;
    S->Mode.CursorColumn = 0;
    S->Mode.CursorRow = 0;
    S->Mode.CursorVisible = TRUE;
    S->TextOut.Reset = ShimOutReset;
    S->TextOut.OutputString = ShimOutputString;
    S->TextOut.TestString = ShimTestString;
    S->TextOut.QueryMode = ShimQueryMode;
    S->TextOut.SetMode = ShimSetMode;
    S->TextOut.SetAttribute = ShimSetAttribute;
    S->TextOut.ClearScreen = ShimClearScreen;
    S->TextOut.SetCursorPosition = ShimSetCursor;
    S->TextOut.EnableCursor = ShimEnableCursor;
    S->TextOut.Mode = &S->Mode;

    S->Handle = NULL;
    st = gBS->InstallMultipleProtocolInterfaces(&S->Handle,
             &gEfiSimpleTextInProtocolGuid, &S->TextIn,
             &gEfiSimpleTextInputExProtocolGuid, &S->TextInEx,
             &gEfiSimpleTextOutProtocolGuid, &S->TextOut,
             NULL);
    if (EFI_ERROR(st)) {
        gBS->CloseEvent(S->TextIn.WaitForKey);
        gBS->CloseEvent(S->TextInEx.WaitForKeyEx);
        return st;
    }

    S->OldConIn = gST->ConIn;
    S->OldConOut = gST->ConOut;
    S->OldStdErr = gST->StdErr;
    S->OldInHandle = gST->ConsoleInHandle;
    S->OldOutHandle = gST->ConsoleOutHandle;
    S->OldErrHandle = gST->StandardErrorHandle;

    gST->ConIn = &S->TextIn;
    gST->ConOut = &S->TextOut;
    gST->StdErr = &S->TextOut;
    gST->ConsoleInHandle = S->Handle;
    gST->ConsoleOutHandle = S->Handle;
    gST->StandardErrorHandle = S->Handle;
    FixCrc();
    S->Installed = TRUE;

    Emit(S, "\x1b[0m");
    Flush(S);
    return EFI_SUCCESS;
}

VOID ShimRemove(CONSOLE_SHIM *S)
{
    if (!S->Installed) {
        return;
    }
    Emit(S, "\x1b[0m\r\n");
    Flush(S);

    gST->ConIn = S->OldConIn;
    gST->ConOut = S->OldConOut;
    gST->StdErr = S->OldStdErr;
    gST->ConsoleInHandle = S->OldInHandle;
    gST->ConsoleOutHandle = S->OldOutHandle;
    gST->StandardErrorHandle = S->OldErrHandle;
    FixCrc();

    gBS->UninstallMultipleProtocolInterfaces(S->Handle,
        &gEfiSimpleTextInProtocolGuid, &S->TextIn,
        &gEfiSimpleTextInputExProtocolGuid, &S->TextInEx,
        &gEfiSimpleTextOutProtocolGuid, &S->TextOut,
        NULL);
    gBS->CloseEvent(S->TextIn.WaitForKey);
    gBS->CloseEvent(S->TextInEx.WaitForKeyEx);
    S->Installed = FALSE;
}
