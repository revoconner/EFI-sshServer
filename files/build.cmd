@echo off
setlocal enabledelayedexpansion
rem Builds SshShell.efi with clang and lld-link, no EDK2 needed. Requires clang, lld-link and python on PATH.

set ROOT=%~dp0
set WOLF=%ROOT%..\wolfssl-5.9.2
set OUT=%ROOT%build
set CFLAGS=-target x86_64-unknown-uefi -ffreestanding -fshort-wchar -mno-red-zone -mno-stack-arg-probe -fno-stack-protector -fno-strict-aliasing -O2 -nostdlibinc -I"%ROOT%include" -I"%ROOT%." -I"%WOLF%" -DWOLFSSL_USER_SETTINGS
set APPFLAGS=-Wall -Wextra -Wno-unused-parameter
set WOLFFLAGS=-Wno-everything

if not exist "%OUT%" mkdir "%OUT%"
if not exist "%ROOT%hostkey.h" (
    python "%ROOT%genkey.py" "%ROOT%hostkey.h" || exit /b 1
)

set OBJS=
for %%f in (SshShellServer ConsoleShim ssh net uefirt) do (
    clang %CFLAGS% %APPFLAGS% -c "%ROOT%%%f.c" -o "%OUT%\%%f.o" || exit /b 1
    set OBJS=!OBJS! "%OUT%\%%f.o"
)
for %%f in (aes sha256 sha512 hmac hash random curve25519 ed25519 fe_operations ge_operations logging error wc_port) do (
    clang %CFLAGS% %WOLFFLAGS% -c "%WOLF%\wolfcrypt\src\%%f.c" -o "%OUT%\wolf_%%f.o" || exit /b 1
    set OBJS=!OBJS! "%OUT%\wolf_%%f.o"
)

lld-link /subsystem:efi_application /entry:EfiMain /nodefaultlib /machine:x64 /out:"%OUT%\SshShell.efi" !OBJS! || exit /b 1
echo Built %OUT%\SshShell.efi
