# Dew: Encrypted HTTPS Reverse Shell

## Overview

Dew is a minimal command-and-control tool designed for penetration testing environments. The project comprises a compact C-based implant (approximately 37 KB) that communicates securely with a Python listener using HTTPS with TLS encryption and an additional XChaCha20-Poly1305 encryption layer over the command channel.

## Key Technical Characteristics

**Transport & Security:**
The system employs native Windows WinHTTP APIs for HTTPS communication with automatically generated self-signed certificates. All command payloads are additionally encrypted with XChaCha20-Poly1305 (AEAD) using a pre-shared key, providing defense-in-depth beyond the TLS transport layer. The implant utilizes system proxy configuration automatically.

**Operational Concealment:**
Callback intervals incorporate randomized jitter via cryptographic randomization (RtlGenRandom), centered around a configurable base interval. Standard browser user-agent headers accompany requests. The binary is stripped and size-optimized at ~37 KB.

**Command Execution:**
Commands are executed via `CreateProcess` with `cmd.exe /c`, capturing stdout and stderr through anonymous pipes. Output is capped at 64 KB with truncation notification. A reserved `EXIT` command provides clean remote shutdown.

**Crypto Implementation:**
XChaCha20-Poly1305 via a minimal extraction of [Monocypher](https://monocypher.org/) (~370 lines). Wire format: `[24-byte nonce][16-byte MAC][ciphertext]`. Fresh random nonces per message eliminate nonce management concerns.

## Development Stack

- **Implant:** C with MinGW cross-compilation
- **Listener:** Python 3 with PyNaCl
- **Crypto:** Monocypher (vendored, minimal extraction)
- **UI Theme:** Catppuccin Mocha color scheme

## Deployment

Generate a shared key, build with `make`, start the listener, and deploy. One command compilation with configurable host, port, and key via Makefile variables.
