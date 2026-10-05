#define _CRT_SECURE_NO_WARNINGS
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "tls_payload.h"

static volatile uint64_t keybank[8] = {
    0x1122334455667788ULL, 0x8877665544332211ULL,
    0x0101010101010101ULL, 0xFEFEFEFEFEFEFEFEULL,
    0xA5A5A5A5A5A5A5A5ULL, 0x5A5A5A5A5A5A5A5AULL,
    0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL
};
static volatile uint64_t initialized = 0;
static volatile uint64_t multipliers[4] = {
    0x9E3779B185EBCA87ULL, 0xC2B2AE3D27D4EB4FULL,
    0xD6E8FEB86659FD93ULL, 0xA24BAED4963EE407ULL
};

static uint64_t rotl64(uint64_t value, unsigned bits) {
    return (value << bits) | (value >> (64 - bits));
}

static uint64_t rotr64(uint64_t value, unsigned bits) {
    return (value >> bits) | (value << (64 - bits));
}

__declspec(noinline) void NTAPI tls_init(PVOID module, DWORD reason, PVOID reserved) {
    uint64_t state = TLS_SEED;
    unsigned i;
    (void)module;
    (void)reserved;
    if (reason != DLL_PROCESS_ATTACH) return;
    for (i = 0; i < 8; ++i) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state = rotl64(state, 11) * 0x94D049BB133111EBULL
              + 0xD1B54A32D192ED03ULL + i;
        keybank[i] = TLS_CIPHER[i] ^ state;
    }
    initialized = 0xC0DEC0DEULL;
}

#pragma section(".CRT$XLB", long, read)
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK tls_callback_slot = tls_init;
#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#endif

__declspec(noinline) uint64_t mix_tls(uint64_t x, uint64_t y) {
    uint64_t a = x ^ keybank[0];
    uint64_t b = y + keybank[1];
    unsigned i;
    for (i = 0; i < 8; ++i) {
        uint64_t u = (a + rotl64(b, 11)) ^ keybank[i];
        uint64_t yes = rotl64(u, 13);
        uint64_t no = rotr64(u ^ keybank[(i + 3) & 7], 17);
        a = ((u ^ x) & 0x200ULL) ? yes : no;
        b = (b ^ a) * multipliers[i & 3] + keybank[(i + 5) & 7];
    }
    return a ^ rotl64(b, 23) ^ ((x * y) * 0x8CB92BA72F3D8DD7ULL);
}

int main(int argc, char **argv) {
    char *end_x = 0, *end_y = 0;
    unsigned long long x, y;
    if (initialized != 0xC0DEC0DEULL || argc != 3) return 2;
    x = _strtoui64(argv[1], &end_x, 0);
    y = _strtoui64(argv[2], &end_y, 0);
    if (!end_x || !end_y || *end_x || *end_y) return 2;
    printf("%016llX\n", (unsigned long long)mix_tls((uint64_t)x, (uint64_t)y));
    return 0;
}
