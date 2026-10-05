#define _CRT_SECURE_NO_WARNINGS
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef VARIANT
#define VARIANT 1
#endif

extern uint64_t check_record(uint64_t x, uint64_t y);
static volatile uint64_t audit_sink;

__declspec(noinline) static uint64_t audit(uint64_t x, uint64_t y) {
    uint64_t z = x ^ 0xD6E8FEB86659FD93ULL;
    unsigned i;
    for (i = 0; i < VARIANT * 3 + 2; ++i) {
        z = (z << 7) | (z >> 57);
        z += y + i * 0x9E3779B185EBCA87ULL;
        if (z & 0x20) z ^= 0xA24BAED4963EE407ULL;
    }
    return z;
}

#if VARIANT >= 2
__declspec(noinline) static uint64_t decoy1(uint64_t x) {
    return (x ^ 0x100ULL) + 0x20ULL;
}
#endif
#if VARIANT >= 3
__declspec(noinline) static uint64_t decoy2(uint64_t x) {
    return (x << 3) ^ (x >> 5) ^ 0x87654321ULL;
}
#endif
#if VARIANT >= 4
__declspec(noinline) static uint64_t decoy3(uint64_t x) {
    return (x * 0xC2B2AE3D27D4EB4FULL) ^ (x >> 7);
}
#endif

int main(int argc, char **argv) {
    char *end_x, *end_y;
    unsigned long long x, y;
    if (argc != 3) return 2;
    x = _strtoui64(argv[1], &end_x, 0);
    y = _strtoui64(argv[2], &end_y, 0);
    if (!end_x || !end_y || *end_x || *end_y) return 2;
    audit_sink = audit((uint64_t)x, (uint64_t)y);
#if VARIANT >= 2
    audit_sink ^= decoy1((uint64_t)x);
#endif
#if VARIANT >= 3
    audit_sink ^= decoy2((uint64_t)y);
#endif
#if VARIANT >= 4
    audit_sink ^= decoy3((uint64_t)x);
#endif
    puts(check_record((uint64_t)x, (uint64_t)y) ? "ACCEPT" : "REJECT");
    return 0;
}
