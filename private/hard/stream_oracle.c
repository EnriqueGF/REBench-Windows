#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "stream_payload.h"

static volatile uint64_t keybank[16] = {
    0x1111111111111111ULL, 0x2222222222222222ULL,
    0x3333333333333333ULL, 0x4444444444444444ULL,
    0x5555555555555555ULL, 0x6666666666666666ULL,
    0x7777777777777777ULL, 0x8888888888888888ULL,
    0x9999999999999999ULL, 0xAAAAAAAAAAAAAAAAULL,
    0xBBBBBBBBBBBBBBBBULL, 0xCCCCCCCCCCCCCCCCULL,
    0xDDDDDDDDDDDDDDDDULL, 0xEEEEEEEEEEEEEEEEULL,
    0x123456789ABCDEF0ULL, 0x0FEDCBA987654321ULL
};
static volatile uint64_t diagnostic_sink;

static uint64_t rotl64(uint64_t x, unsigned bits) {
    return (x << bits) | (x >> (64 - bits));
}

static uint64_t rotr64(uint64_t x, unsigned bits) {
    return (x >> bits) | (x << (64 - bits));
}

__declspec(noinline) int load_keys(void) {
    HRSRC item = FindResourceA(NULL, MAKEINTRESOURCEA(701), RT_RCDATA);
    HGLOBAL handle;
    const uint64_t *cipher;
    uint64_t state = STREAM_SEED;
    unsigned i;
    if (!item || SizeofResource(NULL, item) != 16 * sizeof(uint64_t)) return 0;
    handle = LoadResource(NULL, item);
    if (!handle) return 0;
    cipher = (const uint64_t *)LockResource(handle);
    if (!cipher) return 0;
    for (i = 0; i < 16; ++i) {
        state = rotl64(state ^ (0xA24BAED4963EE407ULL +
                              (uint64_t)i * 0x9E3779B185EBCA87ULL), 9)
              * 0xC2B2AE3D27D4EB4FULL + 0xD1B54A32D192ED03ULL;
        keybank[i] = cipher[i] ^ state;
    }
    return 1;
}

__declspec(noinline) uint64_t stream_tag(const unsigned char *data, size_t n) {
    uint64_t a = keybank[0] ^ ((uint64_t)n * keybank[1]);
    uint64_t b = keybank[2] + ((uint64_t)n ^ keybank[3]);
    size_t i;
    for (i = 0; i < n; ++i) {
        uint64_t byte = data[i];
        uint64_t t = (a + rotl64(b, 11)) ^ (byte + keybank[(i + 3) & 15]);
        t *= keybank[(byte ^ i) & 15];
        if ((byte ^ i) & 4) {
            a = rotl64(t ^ keybank[(byte >> 4) & 15], 17);
        } else {
            a = rotr64(t + keybank[(i + byte) & 15], 13);
        }
        b = (b ^ a) * keybank[(i + 7) & 15]
          + rotl64(byte ^ keybank[(i + 1) & 15], 5);
    }
    return a ^ rotl64(b, 29) ^ keybank[n & 15]
         ^ ((uint64_t)n * 0xD6E8FEB86659FD93ULL);
}

__declspec(noinline) uint64_t decoy_checksum(const unsigned char *data, size_t n) {
    uint64_t v = 0x84222325CBF29CE4ULL;
    size_t i;
    for (i = 0; i < n; ++i) v = rotl64(v ^ data[i], 7) + keybank[i & 15];
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
    size_t length, i;
    uint64_t tag;
    if (argc != 2) return 2;
    if (!strcmp(argv[1], "-")) length = 0;
    else {
        size_t chars = strlen(argv[1]);
        if ((chars & 1) || chars > sizeof(data) * 2) return 2;
        length = chars / 2;
        for (i = 0; i < length; ++i) {
            int hi = nibble(argv[1][i * 2]);
            int lo = nibble(argv[1][i * 2 + 1]);
            if (hi < 0 || lo < 0) return 2;
            data[i] = (unsigned char)((hi << 4) | lo);
        }
    }
    if (!load_keys()) return 3;
    diagnostic_sink = decoy_checksum(data, length);
    tag = stream_tag(data, length);
    printf("%016llX\n", (unsigned long long)tag);
    return 0;
}
