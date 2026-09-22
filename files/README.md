# UEFI x64 SSH Shell server

First working implementation of SSH server inside UEFI pre boot shell environment. Tested on Hypervisor type 1 and type 2.

`SshShell [-p port] [-u user] [-w password] [-s \path\Shell.efi] [-o "shell options"] [-d]`

<img width="3388" height="1311" alt="image" src="https://github.com/user-attachments/assets/64cc5ec6-5c76-4068-a7d3-be30e38c374d" />


**Defaults**:
- port: 22
- user: admin
- password: admin
- path: unmapped
- debug (d): off

## Files

| File | Purpose |
| --- | --- |
| `SshShellServer.c` | entry point, argument parsing, accept loop, nested Shell launch |
| `ssh.c` / `ssh.h` | SSH 2.0 transport, key exchange, password auth, session channel |
| `net.c` / `net.h` | TCP4 listener and connection on top of `EFI_TCP4_PROTOCOL` |
| `ConsoleShim.c` / `.h` | SimpleTextIn, SimpleTextInEx and SimpleTextOut backed by the SSH channel |
| `uefi.h` | minimal UEFI type and protocol definitions, just what this project needs |
| `uefirt.c` / `.h` | globals, tiny `Print`, allocation, entropy, the C library subset wolfCrypt wants |
| `include/` | freestanding `string.h`, `stdlib.h`, `ctype.h` and friends for the UEFI build |
| `user_settings.h` | wolfCrypt configuration for the freestanding build |
| `config.h` | defaults: port, user, password, nested Shell options |
| `hostkey.h` | generated ed25519 host key seed, created by `genkey.py` on first build |
| `build.cmd` | builds `build\SshShell.efi` |
| `test/` | native Windows harness that runs `ssh.c` against real SSH clients |
| `SshShell.inf` | leftover from the EDK2 sketch, not used by this build |

## Build

Requirements: clang and lld-link (LLVM 18 or newer, the UEFI target must exist) and python 3 on PATH. wolfSSL 5.9.2 source is expected at `..\wolfssl-5.9.2` (edit `WOLF` in `build.cmd` otherwise).

```
build.cmd
```

The first run writes `hostkey.h` with a random seed. Keep that file so clients see a stable host key, and keep it private. The server prints the SHA256 fingerprint on start so you can compare it with what the client shows.

Change the defaults in `config.h` (user, password, port) and rebuild, or override them on the command line.

## Run

Networking must be up before the listener can bind. From the Shell on the target:

```
Shell> ifconfig -s eth0 dhcp
Shell> SshShell.efi
```

Options:

```
SshShell.efi [-p port] [-u user] [-w password] [-s \path\Shell.efi] [-o "shell options"] [-d]
```

Defaults are port 22, user `admin`, password `admin`, and the nested Shell gets `-nostartup`. `-d` traces every packet and TCP transfer on the local console, useful when a client hangs. Press ESC or `q` on the local console while the server is waiting for a client to stop it.

From a workstation:

```
ssh admin@<ip>
```

Algorithms offered: `curve25519-sha256` (plus the `@libssh.org` alias), `ssh-ed25519`, `aes128-ctr` / `aes192-ctr` / `aes256-ctr`, `hmac-sha2-256` / `hmac-sha2-512`, no compression.

### Where the nested Shell comes from

1. `-s` path if given
2. the Shell embedded in a firmware volume (standard ShellPkg file GUID, works on OVMF and most EDK2 firmwares)
3. files on the volume `SshShell.efi` was loaded from, in this order: `Shell.efi` and `shellx64.efi` next to `SshShell.efi`, then `\Shell.efi`, `\shellx64.efi`, `\EFI\Shell.efi`, `\EFI\shellx64.efi`, `\EFI\Boot\Shell.efi`, `\EFI\Boot\shellx64.efi`, `\EFI\Tools\Shell.efi`

Hyper-V firmware has no Shell in its volumes, so on that VM the file fallback is what gets used.


## Limitations

- Password auth only, one user. Public key auth is not implemented.
- One session per connection, one connection at a time. Other clients wait in the TCP backlog.
- Rekeying initiated by the client is handled. The server never initiates one.
- Colors are mapped to the 16 ANSI colors, nothing fancier. Non BMP characters are dropped on input.
- The host key seed lives in the binary. Anyone with the .efi can extract it.
- Not hardened against a hostile network. Use on a lab network.


## AI Use

Co-Authored by Anthropic Claude Fable 5.1 <claude@anthropic.com>
