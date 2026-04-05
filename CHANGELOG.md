# Changelog

All notable changes to Dew will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-04

### Added
- XChaCha20-Poly1305 AEAD encryption via vendored Monocypher extraction (~370 lines)
- HTTPS reverse shell implant in C (~390 lines, ~37 KB compiled)
- WinHTTP transport with native TLS and system proxy support
- Pre-shared 256-bit key authentication
- Fresh 24-byte random nonce per message via RtlGenRandom
- Jittered callback intervals with configurable base sleep and jitter percentage
- Piped command execution via CreateProcess with 64 KB output cap
- Remote EXIT command for clean shutdown
- Python HTTPS listener with interactive CLI and auto self-signed cert generation
- One-command build script with automatic PSK generation
- Makefile with MinGW-w64 cross-compilation targets
