#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "stream2_payload.h"

static volatile uint64_t keybank[16] = {
    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16
};
static volatile int key_ready;
static volatile uint64_t audit_sink;

static uint64_t rol64(uint64_t value, unsigned bits) {
    return (value << bits) | (value >> (64 - bits));
}
static uint64_t ror64(uint64_t value, unsigned bits) {
    return (value >> bits) | (value << (64 - bits));
}

__declspec(noinline) void NTAPI stream2_tls(PVOID module, DWORD reason, PVOID reserved) {
    HRSRC item;
    HGLOBAL handle;
    const uint64_t *cipher;
    uint64_t state = STREAM2_SEED;
    unsigned i;
    (void)reserved;
    if (reason != DLL_PROCESS_ATTACH) return;
    item = FindResourceA((HMODULE)module, MAKEINTRESOURCEA(803), RT_RCDATA);
    if (!item || SizeofResource((HMODULE)module, item) != 16 * sizeof(uint64_t)) return;
    handle = LoadResource((HMODULE)module, item);
    if (!handle) return;
    cipher = (const uint64_t *)LockResource(handle);
    if (!cipher) return;
    for (i = 0; i < 16; ++i) {
        state = rol64(state ^ (0x79B5D06C8A4E3F21ULL +
                              (uint64_t)i * 0x9E3779B185EBCA87ULL), 7)
              * 0xD6E8FEB86659FD93ULL + 0xA24BAED4963EE407ULL;
        keybank[i] = cipher[i] ^ state;
    }
    key_ready = 1;
}

#pragma section(".CRT$XLB", long, read)
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK stream2_slot = stream2_tls;
#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#endif

__declspec(noinline) uint64_t two_pass_tag(const unsigned char *data, size_t n) {
    uint64_t a = keybank[0] ^ ((uint64_t)n * keybank[1]);
    uint64_t b = keybank[2] + ((uint64_t)n ^ keybank[3]);
    size_t i;
    for (i = 0; i < n; ++i) {
        uint64_t byte = data[i];
        uint64_t t = (a + rol64(b, 7)) ^ (byte + keybank[(i + 5) & 15]);
        t *= keybank[(i + byte) & 15];
        if ((byte ^ i) & 1) {
            a = rol64(t ^ keybank[(byte >> 4) & 15], 13);
        } else {
            a = ror64(t + keybank[(i + 3) & 15], 11);
        }
        b = (b ^ a) * keybank[(i + 11) & 15] + byte;
    }
    for (i = n; i != 0;) {
        uint64_t byte = data[--i];
        uint64_t z = (b ^ ror64(a, 9)) + keybank[(i + byte) & 15];
        if ((byte ^ i) & 0x20) {
            b = rol64(z ^ keybank[(i + 7) & 15], 17);
        } else {
            b = ror64(z + keybank[(byte >> 4) & 15], 19);
        }
        a = (a + b) * keybank[(i + 1) & 15]
          ^ rol64(byte + keybank[(i + 2) & 15], 5);
    }
    return a ^ rol64(b, 29) ^ keybank[n & 15]
         ^ ((uint64_t)n * 0x8CB92BA72F3D8DD7ULL);
}

__declspec(noinline) uint64_t audit_checksum(const unsigned char *data, size_t n) {
    uint64_t v = 0x735E2D9C4A681B0FULL;
    size_t i;
    for (i = 0; i < n; ++i) v = rol64(v ^ data[i], 11) + keybank[i & 15];
    return v;
}

static int nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

int main(int argc, char **argv) {
    unsigned char data[96];
    size_t n, i, chars;
    if (argc != 2 || !key_ready) return 2;
    if (!strcmp(argv[1], "-")) n = 0;
    else {
        chars = strlen(argv[1]);
        if ((chars & 1) || chars > sizeof(data) * 2) return 2;
        n = chars / 2;
        for (i = 0; i < n; ++i) {
            int hi = nibble(argv[1][2 * i]);
            int lo = nibble(argv[1][2 * i + 1]);
            if (hi < 0 || lo < 0) return 2;
            data[i] = (unsigned char)((hi << 4) | lo);
        }
    }
    audit_sink = audit_checksum(data, n);
    printf("%016llX\n", (unsigned long long)two_pass_tag(data, n));
    return 0;
}
