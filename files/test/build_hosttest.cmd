@echo off
setlocal enabledelayedexpansion
rem Builds the native host test that links ssh.c and wolfCrypt as a Windows program.

set ROOT=%~dp0..\
set WOLF=%ROOT%..\wolfssl-5.9.2
set OUT=%ROOT%build\host
set CFLAGS=-O1 -g -I"%ROOT%." -I"%WOLF%" -DWOLFSSL_USER_SETTINGS -D_CRT_SECURE_NO_WARNINGS -DWOLFSSL_HAVE_MIN -DWOLFSSL_HAVE_MAX

if not exist "%OUT%" mkdir "%OUT%"

set OBJS=
for %%f in (hosttest hoststubs hostsock) do (
    clang %CFLAGS% -Wall -c "%ROOT%test\%%f.c" -o "%OUT%\%%f.o" || exit /b 1
    set OBJS=!OBJS! "%OUT%\%%f.o"
)
clang %CFLAGS% -Wall -Wextra -c "%ROOT%ssh.c" -o "%OUT%\ssh.o" || exit /b 1
set OBJS=!OBJS! "%OUT%\ssh.o"
for %%f in (aes sha256 sha512 hmac hash random curve25519 ed25519 fe_operations ge_operations logging error wc_port) do (
    clang %CFLAGS% -Wno-everything -c "%WOLF%\wolfcrypt\src\%%f.c" -o "%OUT%\wolf_%%f.o" || exit /b 1
    set OBJS=!OBJS! "%OUT%\wolf_%%f.o"
)
clang -g -o "%OUT%\hosttest.exe" !OBJS! -lws2_32 -ladvapi32 || exit /b 1
clang -O1 -o "%OUT%\askpass.exe" "%ROOT%test\askpass.c" || exit /b 1
echo Built %OUT%\hosttest.exe
