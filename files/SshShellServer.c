/** @file
  UEFI SSH server, entry point and orchestration.

  Flow:
    1. bring up a TCP4 listener on port 22 (networking must already be up,
       see README, run ifconfig dhcp first or set a static address)
    2. accept one connection
    3. stand up a wolfSSH session on top of that socket
    4. install the console shim and launch a nested EDK2 Shell
    5. when the Shell exits, tear down and go back to step 2

  This is a sketch. The host key and user auth are placeholders. Do not put
  this on a real network as-is.
*/

#include "ConsoleShim.h"
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Protocol/ServiceBinding.h>
#include <Protocol/FirmwareVolume2.h>

// UEFI Shell 2.x file GUID inside the firmware volume. This is the standard
// one from ShellPkg. If your build uses a different shell, change this.
STATIC CONST EFI_GUID mShellFileGuid = {
  0x7C04A583, 0x9E3E, 0x4f1c, { 0xAD, 0x65, 0xE0, 0x52, 0x68, 0xD0, 0xB4, 0xD1 }
};

#define SSH_PORT 22

// ---- host key (PLACEHOLDER) ----------------------------------------------
// Drop a real key here. DER format ECC or RSA private key bytes. Easiest is to
// generate one on your workstation and xxd -i it into a C array. Loading from a
// file is possible too but there is no filesystem guarantee at this layer.
STATIC CONST UINT8 mHostKeyDer[] = { 0x00 };   // TODO: replace
STATIC CONST UINTN mHostKeyLen   = 0;          // TODO: set real length

// ---- user auth (PLACEHOLDER) ---------------------------------------------
// Accepts user "admin" password "admin". Obviously replace this. Prefer pubkey
// auth: compare the offered key against an allowed key you baked in.
STATIC int UserAuthCb (byte authType, WS_UserAuthData *authData, void *ctx) {
  (void)ctx;
  if (authType == WOLFSSH_USERAUTH_PASSWORD) {
    CONST char *user = "admin";
    CONST char *pass = "admin";
    if (authData->username != NULL &&
        authData->sf.password.passwordSz == 5 &&
        CompareMem (authData->username, user, 5) == 0 &&
        CompareMem (authData->sf.password.password, pass, 5) == 0) {
      return WOLFSSH_USERAUTH_SUCCESS;
    }
    return WOLFSSH_USERAUTH_INVALID_PASSWORD;
  }
  // TODO: WOLFSSH_USERAUTH_PUBLICKEY branch
  return WOLFSSH_USERAUTH_FAILURE;
}

// ---- TCP listen + accept --------------------------------------------------

STATIC EFI_STATUS
ListenAndAccept (
  OUT EFI_TCP4_PROTOCOL **ConnTcp,
  OUT EFI_HANDLE         *ConnHandle,
  OUT EFI_HANDLE         *ListenChild,
  OUT EFI_SERVICE_BINDING_PROTOCOL **Sb
  )
{
  EFI_STATUS                    Status;
  EFI_SERVICE_BINDING_PROTOCOL *Tcp4Sb;
  EFI_HANDLE                    Child = NULL;
  EFI_TCP4_PROTOCOL            *Listen;
  EFI_TCP4_CONFIG_DATA          Cfg;
  EFI_TCP4_LISTEN_TOKEN         AcceptTok;
  UINTN                         idx;

  Status = gBS->LocateProtocol (&gEfiTcp4ServiceBindingProtocolGuid, NULL, (VOID **)&Tcp4Sb);
  if (EFI_ERROR (Status)) {
    Print (L"No TCP4 service binding. Is networking up?\n");
    return Status;
  }

  Status = Tcp4Sb->CreateChild (Tcp4Sb, &Child);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = gBS->OpenProtocol (
             Child, &gEfiTcp4ProtocolGuid, (VOID **)&Listen,
             gImageHandle, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL
             );
  if (EFI_ERROR (Status)) {
    Tcp4Sb->DestroyChild (Tcp4Sb, Child);
    return Status;
  }

  ZeroMem (&Cfg, sizeof (Cfg));
  Cfg.TypeOfService              = 0;
  Cfg.TimeToLive                 = 64;
  Cfg.AccessPoint.UseDefaultAddress = TRUE;   // use the station address already set
  Cfg.AccessPoint.StationPort    = SSH_PORT;
  Cfg.AccessPoint.ActiveFlag     = FALSE;     // passive, we listen

  Status = Listen->Configure (Listen, &Cfg);
  if (EFI_ERROR (Status)) {
    Print (L"TCP Configure failed: %r. Set an IP first (dhcp or static).\n", Status);
    Tcp4Sb->DestroyChild (Tcp4Sb, Child);
    return Status;
  }

  ZeroMem (&AcceptTok, sizeof (AcceptTok));
  Status = gBS->CreateEvent (0, TPL_CALLBACK, NULL, NULL, &AcceptTok.CompletionToken.Event);
  if (EFI_ERROR (Status)) {
    Tcp4Sb->DestroyChild (Tcp4Sb, Child);
    return Status;
  }

  Print (L"Listening on port %d ...\n", SSH_PORT);
  Status = Listen->Accept (Listen, &AcceptTok);
  if (EFI_ERROR (Status)) {
    gBS->CloseEvent (AcceptTok.CompletionToken.Event);
    Tcp4Sb->DestroyChild (Tcp4Sb, Child);
    return Status;
  }

  gBS->WaitForEvent (1, &AcceptTok.CompletionToken.Event, &idx);
  gBS->CloseEvent (AcceptTok.CompletionToken.Event);

  Status = AcceptTok.CompletionToken.Status;
  if (EFI_ERROR (Status)) {
    Tcp4Sb->DestroyChild (Tcp4Sb, Child);
    return Status;
  }

  // AcceptTok.NewChildHandle is the connected socket
  Status = gBS->OpenProtocol (
             AcceptTok.NewChildHandle, &gEfiTcp4ProtocolGuid, (VOID **)ConnTcp,
             gImageHandle, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  *ConnHandle  = AcceptTok.NewChildHandle;
  *ListenChild = Child;
  *Sb          = Tcp4Sb;
  return EFI_SUCCESS;
}

// ---- load and run the shell ----------------------------------------------
// Pull the Shell PE32 straight out of whatever firmware volume has it, load it
// with a source buffer, and start it. It inherits our swapped gST console.

STATIC EFI_STATUS LaunchShell (VOID) {
  EFI_STATUS                     Status;
  EFI_HANDLE                    *Fvs = NULL;
  UINTN                          FvCount = 0, i;
  EFI_FIRMWARE_VOLUME2_PROTOCOL *Fv;
  VOID                          *Pe = NULL;
  UINTN                          PeSize = 0;
  UINT32                         AuthStatus;
  EFI_HANDLE                     ShellHandle = NULL;
  UINTN                          ExitSize = 0;
  CHAR16                        *ExitData = NULL;

  Status = gBS->LocateHandleBuffer (
             ByProtocol, &gEfiFirmwareVolume2ProtocolGuid, NULL, &FvCount, &Fvs
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  for (i = 0; i < FvCount; i++) {
    Status = gBS->HandleProtocol (Fvs[i], &gEfiFirmwareVolume2ProtocolGuid, (VOID **)&Fv);
    if (EFI_ERROR (Status)) {
      continue;
    }
    Pe = NULL; PeSize = 0;
    Status = Fv->ReadSection (
               Fv, &mShellFileGuid, EFI_SECTION_PE32, 0,
               &Pe, &PeSize, &AuthStatus
               );
    if (!EFI_ERROR (Status) && Pe != NULL) {
      break; // found it
    }
  }
  gBS->FreePool (Fvs);

  if (Pe == NULL) {
    Print (L"Shell not found in any FV. Put ShellPkg Shell in your build.\n");
    return EFI_NOT_FOUND;
  }

  Status = gBS->LoadImage (FALSE, gImageHandle, NULL, Pe, PeSize, &ShellHandle);
  gBS->FreePool (Pe);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  // this blocks until the shell session exits (user types exit)
  Status = gBS->StartImage (ShellHandle, &ExitSize, &ExitData);
  if (ExitData != NULL) {
    gBS->FreePool (ExitData);
  }
  return Status;
}

// ---- one client session ---------------------------------------------------

STATIC VOID RunSession (SSH_SESSION *S) {
  int ret;

  S->Ctx = wolfSSH_CTX_new (WOLFSSH_ENDPOINT_SERVER, NULL);
  if (S->Ctx == NULL) {
    Print (L"wolfSSH_CTX_new failed\n");
    return;
  }

  wolfSSH_SetIORecv (S->Ctx, SshRecvCb);
  wolfSSH_SetIOSend (S->Ctx, SshSendCb);
  wolfSSH_SetUserAuth (S->Ctx, UserAuthCb);

  if (mHostKeyLen == 0 ||
      wolfSSH_CTX_UsePrivateKey_buffer (S->Ctx, mHostKeyDer, mHostKeyLen,
                                        WOLFSSH_FORMAT_ASN1) < 0) {
    Print (L"Host key not set. Fill in mHostKeyDer.\n");
    wolfSSH_CTX_free (S->Ctx);
    S->Ctx = NULL;
    return;
  }

  S->Ssh = wolfSSH_new (S->Ctx);
  if (S->Ssh == NULL) {
    Print (L"wolfSSH_new failed\n");
    wolfSSH_CTX_free (S->Ctx);
    S->Ctx = NULL;
    return;
  }

  wolfSSH_SetIOReadCtx (S->Ssh, S);
  wolfSSH_SetIOWriteCtx (S->Ssh, S);
  wolfSSH_SetUserAuthCtx (S->Ssh, S);

  S->Connected = TRUE;
  ArmReceive (S);   // start draining TCP into the raw ring

  // handshake. non blocking, so loop while it wants more IO.
  do {
    ret = wolfSSH_accept (S->Ssh);
    S->Tcp->Poll (S->Tcp);
  } while (ret == WS_WANT_READ || ret == WS_WANT_WRITE);

  if (ret != WS_SUCCESS) {
    Print (L"wolfSSH_accept failed: %d\n", ret);
  } else {
    // channel is open and the client asked for a shell. redirect and run it.
    if (!EFI_ERROR (InstallConsoleShim (S))) {
      LaunchShell ();
      RemoveConsoleShim (S);
    }
  }

  S->Connected = FALSE;
  wolfSSH_stream_exit (S->Ssh, 0);
  wolfSSH_free (S->Ssh);
  wolfSSH_CTX_free (S->Ctx);
  S->Ssh = NULL;
  S->Ctx = NULL;
}

// ---- entry ----------------------------------------------------------------

EFI_STATUS EFIAPI SshShellEntry (
  IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable
  ) {
  EFI_STATUS                    Status;
  SSH_SESSION                  *S;
  EFI_SERVICE_BINDING_PROTOCOL *Sb = NULL;
  EFI_HANDLE                    ListenChild = NULL;
  EFI_HANDLE                    ConnHandle  = NULL;

  (void)ImageHandle; (void)SystemTable;

  if (wolfSSH_Init () != WS_SUCCESS) {
    Print (L"wolfSSH_Init failed\n");
    return EFI_DEVICE_ERROR;
  }

  S = AllocateZeroPool (sizeof (SSH_SESSION));
  if (S == NULL) {
    wolfSSH_Cleanup ();
    return EFI_OUT_OF_RESOURCES;
  }

  // one shot for now. wrap this in a while(1) once you are happy it is stable.
  Status = ListenAndAccept (&S->Tcp, &ConnHandle, &ListenChild, &Sb);
  if (!EFI_ERROR (Status)) {
    Print (L"Client connected. Starting SSH.\n");
    RunSession (S);

    // close the connection child, then the listener child
    if (Sb != NULL && ConnHandle != NULL) {
      Sb->DestroyChild (Sb, ConnHandle);
    }
    if (Sb != NULL && ListenChild != NULL) {
      Sb->DestroyChild (Sb, ListenChild);
    }
  }

  FreePool (S);
  wolfSSH_Cleanup ();
  return Status;
}
