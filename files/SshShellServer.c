/* UEFI SSH server entry point.

   Flow:
     1. bind a TCP4 listener (networking must already be up, see README.md)
     2. accept one client, run the SSH handshake and password auth
     3. swap gST->ConIn/ConOut for the console shim and start a nested Shell
     4. when the Shell exits, restore the console, close the session, go back to 2
   Press ESC or q on the local console while it is waiting for a client to quit. */

#include "uefirt.h"
#include "net.h"
#include "ssh.h"
#include "ConsoleShim.h"
#include "config.h"
#include "hostkey.h"
#include <string.h>

typedef struct {
    char   User[64];
    char   Pass[128];
    UINT16 Port;
    CHAR16 ShellPath[260];
    CHAR16 ShellOpts[128];
} SERVER_CFG;

static SERVER_CFG mCfg;

/* Standard ShellPkg file GUID inside a firmware volume. */
static EFI_GUID mShellFileGuid = { 0x7C04A583, 0x9E3E, 0x4f1c, { 0xAD, 0x65, 0xE0, 0x52, 0x68, 0xD0, 0xB4, 0xD1 } };

static UINTN StrLen16(const CHAR16 *s)
{
    UINTN n = 0;
    while (s[n] != 0) {
        n++;
    }
    return n;
}

static void StrCpy16(CHAR16 *d, const CHAR16 *s, UINTN cap)
{
    UINTN i = 0;
    while (i + 1 < cap && s[i] != 0) {
        d[i] = s[i];
        i++;
    }
    d[i] = 0;
}

static void StrCat16(CHAR16 *d, const CHAR16 *s, UINTN cap)
{
    UINTN n = StrLen16(d);
    StrCpy16(d + n, s, cap - n);
}

static BOOLEAN ConstantTimeEq(const char *a, const char *b)
{
    UINTN la = strlen(a);
    UINTN lb = strlen(b);
    UINTN i;
    UINT8 diff = (UINT8)(la != lb);
    for (i = 0; i < la; i++) {
        diff |= (UINT8)(a[i] ^ b[i % (lb ? lb : 1)]);
    }
    return (BOOLEAN)(diff == 0);
}

static BOOLEAN CheckPassword(void *ctx, const char *user, const char *pass)
{
    (void)ctx;
    return (BOOLEAN)(ConstantTimeEq(user, mCfg.User) && ConstantTimeEq(pass, mCfg.Pass));
}

/* Command line */

static void ToAscii(const CHAR16 *s, char *d, UINTN cap)
{
    UINTN i = 0;
    while (i + 1 < cap && s[i] != 0) {
        d[i] = (s[i] < 0x80) ? (char)s[i] : '?';
        i++;
    }
    d[i] = 0;
}

static void Usage(void)
{
    Print("Usage: SshShell.efi [-p port] [-u user] [-w password] [-s \\path\\Shell.efi] [-o \"shell options\"]\n");
    Print("  Defaults: port %u, user %s, shell options \"%s\"\n", SSH_DEFAULT_PORT, SSH_DEFAULT_USER, SSH_DEFAULT_SHELL_OPTS);
}

static BOOLEAN ParseArgs(void)
{
    EFI_LOADED_IMAGE_PROTOCOL *li = NULL;
    CHAR16 *opts;
    CHAR16 *argv[24];
    UINTN   argc = 0;
    UINTN   i;
    CHAR16  buf[512];
    CHAR16 *p;
    char    tmp[16];

    strncpy(mCfg.User, SSH_DEFAULT_USER, sizeof(mCfg.User) - 1);
    strncpy(mCfg.Pass, SSH_DEFAULT_PASS, sizeof(mCfg.Pass) - 1);
    mCfg.Port = SSH_DEFAULT_PORT;
    mCfg.ShellPath[0] = 0;
    for (i = 0; SSH_DEFAULT_SHELL_OPTS[i] != 0 && i + 1 < 128; i++) {
        mCfg.ShellOpts[i] = (CHAR16)SSH_DEFAULT_SHELL_OPTS[i];
    }
    mCfg.ShellOpts[i] = 0;

    if (EFI_ERROR(gBS->HandleProtocol(gImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **)&li)) || li == NULL || li->LoadOptions == NULL || li->LoadOptionsSize < 2) {
        return TRUE;
    }
    opts = li->LoadOptions;
    StrCpy16(buf, opts, li->LoadOptionsSize / 2 < 512 ? li->LoadOptionsSize / 2 + 1 : 512);

    /* Tokenize on spaces, honouring double quotes. */
    p = buf;
    while (*p != 0 && argc < 24) {
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (*p == 0) {
            break;
        }
        if (*p == '"') {
            p++;
            argv[argc++] = p;
            while (*p != 0 && *p != '"') {
                p++;
            }
        } else {
            argv[argc++] = p;
            while (*p != 0 && *p != ' ' && *p != '\t') {
                p++;
            }
        }
        if (*p != 0) {
            *p++ = 0;
        }
    }

    for (i = 0; i < argc; i++) {
        CHAR16 *a = argv[i];
        if (a[0] != '-') {
            continue;
        }
        if (a[1] == 'h' || a[1] == '?') {
            Usage();
            return FALSE;
        }
        if (i + 1 >= argc) {
            Usage();
            return FALSE;
        }
        switch (a[1]) {
        case 'p':
            ToAscii(argv[++i], tmp, sizeof(tmp));
            mCfg.Port = (UINT16)atoi(tmp);
            break;
        case 'u':
            ToAscii(argv[++i], mCfg.User, sizeof(mCfg.User));
            break;
        case 'w':
            ToAscii(argv[++i], mCfg.Pass, sizeof(mCfg.Pass));
            break;
        case 's':
            StrCpy16(mCfg.ShellPath, argv[++i], 260);
            break;
        case 'o':
            StrCpy16(mCfg.ShellOpts, argv[++i], 128);
            break;
        default:
            Usage();
            return FALSE;
        }
    }
    if (mCfg.Port == 0) {
        mCfg.Port = SSH_DEFAULT_PORT;
    }
    return TRUE;
}

/* Shell launch */

static EFI_STATUS StartImageWithOpts(EFI_HANDLE img)
{
    EFI_LOADED_IMAGE_PROTOCOL *li = NULL;
    UINTN   exitSize = 0;
    CHAR16 *exitData = NULL;
    EFI_STATUS st;

    if (mCfg.ShellOpts[0] != 0 && !EFI_ERROR(gBS->HandleProtocol(img, &gEfiLoadedImageProtocolGuid, (VOID **)&li)) && li != NULL) {
        li->LoadOptions = mCfg.ShellOpts;
        li->LoadOptionsSize = (UINT32)((StrLen16(mCfg.ShellOpts) + 1) * 2);
    }
    st = gBS->StartImage(img, &exitSize, &exitData);
    if (exitData != NULL) {
        gBS->FreePool(exitData);
    }
    return st;
}

static EFI_STATUS TryFv(void)
{
    EFI_STATUS  st;
    EFI_HANDLE *fvs = NULL;
    UINTN       count = 0;
    UINTN       i;

    st = gBS->LocateHandleBuffer(ByProtocol, &gEfiFirmwareVolume2ProtocolGuid, NULL, &count, &fvs);
    if (EFI_ERROR(st) || fvs == NULL) {
        return EFI_NOT_FOUND;
    }
    for (i = 0; i < count; i++) {
        EFI_FIRMWARE_VOLUME2_PROTOCOL *fv = NULL;
        VOID   *pe = NULL;
        UINTN   peSize = 0;
        UINT32  auth = 0;
        EFI_HANDLE img = NULL;
        if (EFI_ERROR(gBS->HandleProtocol(fvs[i], &gEfiFirmwareVolume2ProtocolGuid, (VOID **)&fv)) || fv == NULL) {
            continue;
        }
        st = fv->ReadSection(fv, &mShellFileGuid, EFI_SECTION_PE32, 0, &pe, &peSize, &auth);
        if (EFI_ERROR(st) || pe == NULL) {
            continue;
        }
        st = gBS->LoadImage(FALSE, gImageHandle, NULL, pe, peSize, &img);
        gBS->FreePool(pe);
        if (EFI_ERROR(st)) {
            continue;
        }
        gBS->FreePool(fvs);
        Print("Starting the firmware volume Shell\n");
        return StartImageWithOpts(img);
    }
    gBS->FreePool(fvs);
    return EFI_NOT_FOUND;
}

static UINTN DevPathLen(EFI_DEVICE_PATH_PROTOCOL *dp)
{
    UINTN total = 0;
    for (;;) {
        UINTN len = dp->Length[0] | ((UINTN)dp->Length[1] << 8);
        if (len < 4) {
            return total;
        }
        if (dp->Type == END_DEVICE_PATH_TYPE && dp->SubType == END_ENTIRE_DEVICE_PATH_SUBTYPE) {
            return total;
        }
        total += len;
        dp = (EFI_DEVICE_PATH_PROTOCOL *)((UINT8 *)dp + len);
    }
}

/* Directory of our own image, from the file path node of LoadedImage->FilePath, with the trailing backslash. */
static void OwnDirectory(EFI_LOADED_IMAGE_PROTOCOL *li, CHAR16 *out, UINTN cap)
{
    EFI_DEVICE_PATH_PROTOCOL *dp = li->FilePath;
    out[0] = 0;
    if (dp == NULL) {
        return;
    }
    for (;;) {
        UINTN len = dp->Length[0] | ((UINTN)dp->Length[1] << 8);
        if (len < 4 || (dp->Type == END_DEVICE_PATH_TYPE && dp->SubType == END_ENTIRE_DEVICE_PATH_SUBTYPE)) {
            break;
        }
        if (dp->Type == MEDIA_DEVICE_PATH && dp->SubType == MEDIA_FILEPATH_DP) {
            CHAR16 *path = (CHAR16 *)((UINT8 *)dp + 4);
            UINTN   chars = (len - 4) / 2;
            UINTN   i, cut = 0;
            for (i = 0; i < chars && path[i] != 0; i++) {
                if (path[i] == '\\') {
                    cut = i + 1;
                }
            }
            if (cut + 1 < cap) {
                memcpy(out, path, cut * 2);
                out[cut] = 0;
            }
        }
        dp = (EFI_DEVICE_PATH_PROTOCOL *)((UINT8 *)dp + len);
    }
}

static EFI_STATUS TryFile(EFI_LOADED_IMAGE_PROTOCOL *li, const CHAR16 *path)
{
    EFI_DEVICE_PATH_PROTOCOL *devDp = NULL;
    EFI_DEVICE_PATH_PROTOCOL *dp, *node;
    UINTN      devLen, nodeLen, pathChars;
    EFI_HANDLE img = NULL;
    EFI_STATUS st;

    if (li->DeviceHandle == NULL || path[0] == 0) {
        return EFI_NOT_FOUND;
    }
    if (EFI_ERROR(gBS->HandleProtocol(li->DeviceHandle, &gEfiDevicePathProtocolGuid, (VOID **)&devDp)) || devDp == NULL) {
        return EFI_NOT_FOUND;
    }
    devLen = DevPathLen(devDp);
    pathChars = StrLen16(path) + 1;
    nodeLen = 4 + pathChars * 2;
    dp = RtAllocZero(devLen + nodeLen + 4);
    if (dp == NULL) {
        return EFI_OUT_OF_RESOURCES;
    }
    memcpy(dp, devDp, devLen);
    node = (EFI_DEVICE_PATH_PROTOCOL *)((UINT8 *)dp + devLen);
    node->Type = MEDIA_DEVICE_PATH;
    node->SubType = MEDIA_FILEPATH_DP;
    node->Length[0] = (UINT8)nodeLen;
    node->Length[1] = (UINT8)(nodeLen >> 8);
    memcpy((UINT8 *)node + 4, path, pathChars * 2);
    node = (EFI_DEVICE_PATH_PROTOCOL *)((UINT8 *)node + nodeLen);
    node->Type = END_DEVICE_PATH_TYPE;
    node->SubType = END_ENTIRE_DEVICE_PATH_SUBTYPE;
    node->Length[0] = 4;
    node->Length[1] = 0;

    st = gBS->LoadImage(FALSE, gImageHandle, dp, NULL, 0, &img);
    RtFree(dp);
    if (EFI_ERROR(st)) {
        return st;
    }
    {
        char a[260];
        ToAscii(path, a, sizeof(a));
        Print("Starting %s\n", a);
    }
    return StartImageWithOpts(img);
}

static EFI_STATUS LaunchShell(void)
{
    static const CHAR16 *candidates[] = {
        L"Shell.efi", L"shellx64.efi",
        L"\\Shell.efi", L"\\shellx64.efi",
        L"\\EFI\\Shell.efi", L"\\EFI\\shellx64.efi",
        L"\\EFI\\Boot\\Shell.efi", L"\\EFI\\Boot\\shellx64.efi",
        L"\\EFI\\Tools\\Shell.efi",
    };
    EFI_LOADED_IMAGE_PROTOCOL *li = NULL;
    CHAR16     dir[260];
    CHAR16     full[520];
    EFI_STATUS st;
    UINTN      i;

    if (EFI_ERROR(gBS->HandleProtocol(gImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **)&li)) || li == NULL) {
        return EFI_NOT_FOUND;
    }
    if (mCfg.ShellPath[0] != 0) {
        st = TryFile(li, mCfg.ShellPath);
        if (st != EFI_NOT_FOUND) {
            return st;
        }
        Print("Shell not found at the -s path, trying the defaults\n");
    }
    st = TryFv();
    if (st != EFI_NOT_FOUND) {
        return st;
    }
    OwnDirectory(li, dir, 260);
    for (i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        if (candidates[i][0] != '\\') {
            if (dir[0] == 0) {
                continue;
            }
            StrCpy16(full, dir, 520);
            StrCat16(full, candidates[i], 520);
        } else {
            StrCpy16(full, candidates[i], 520);
        }
        st = TryFile(li, full);
        if (st != EFI_NOT_FOUND) {
            return st;
        }
    }
    return EFI_NOT_FOUND;
}

/* Entry */

EFI_STATUS EFIAPI EfiMain(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_STATUS    st;
    NET_CONN     *conn;
    CONSOLE_SHIM *shim;
    UINTN         failures = 0;

    RtInit(ImageHandle, SystemTable);
    if (!ParseArgs()) {
        return EFI_INVALID_PARAMETER;
    }
    gBS->SetWatchdogTimer(0, 0, 0, NULL);

    Print("UEFI SSH Shell server\n");
    SshPrintHostKey(HOST_KEY_SEED);
    Print("Login: user %s\n", mCfg.User);

    conn = RtAllocZero(sizeof(NET_CONN));
    shim = RtAllocZero(sizeof(CONSOLE_SHIM));
    if (conn == NULL || shim == NULL) {
        Print("Out of memory\n");
        return EFI_OUT_OF_RESOURCES;
    }

    st = NetListenStart(mCfg.Port);
    if (EFI_ERROR(st)) {
        RtFree(conn);
        RtFree(shim);
        return st;
    }

    for (;;) {
        SSH_CONN *ssh;

        Print("Waiting for a client. Press ESC or q here to stop.\n");
        st = NetAccept(conn);
        if (st == EFI_ABORTED) {
            break;
        }
        if (EFI_ERROR(st)) {
            if (++failures >= 5) {
                Print("Giving up after repeated accept failures\n");
                break;
            }
            gBS->Stall(500000);
            continue;
        }
        failures = 0;
        Print("Client %d.%d.%d.%d:%u connected\n", conn->Remote.Addr[0], conn->Remote.Addr[1], conn->Remote.Addr[2], conn->Remote.Addr[3], conn->RemotePort);

        ssh = SshNew(NetRead, NetWrite, conn, HOST_KEY_SEED, CheckPassword, NULL);
        if (ssh == NULL) {
            NetCloseConn(conn);
            continue;
        }
        if (SshAccept(ssh) == 0) {
            Print("Session for %s started. This console is redirected until the Shell exits.\n", SshUser(ssh));
            st = ShimInstall(shim, ssh);
            if (!EFI_ERROR(st)) {
                st = LaunchShell();
                ShimRemove(shim);
                if (EFI_ERROR(st)) {
                    static const char msg[] = "\r\nNo UEFI Shell image could be started on this system. Put Shell.efi next to SshShell.efi or pass -s.\r\n";
                    Print("Could not start a Shell: %r\n", st);
                    SshWrite(ssh, (const UINT8 *)msg, sizeof(msg) - 1);
                }
            } else {
                Print("Console shim install failed: %r\n", st);
            }
        }
        SshClose(ssh, 0);
        SshFree(ssh);
        NetCloseConn(conn);
        Print("Session ended\n");
    }

    NetListenStop();
    RtFree(conn);
    RtFree(shim);
    Print("Server stopped\n");
    return EFI_SUCCESS;
}
