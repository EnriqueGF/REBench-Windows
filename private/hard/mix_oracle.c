#define _CRT_SECURE_NO_WARNINGS
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static volatile uint64_t key_a = 0xD6E8FEB86659FD93ULL;
static volatile uint64_t key_b = 0x9E3779B185EBCA87ULL;
static volatile uint64_t key_c = 0xA0761D6478BD642FULL;
static volatile uint64_t key_d = 0xE7037ED1A0B428DBULL;
static volatile uint64_t key_e = 0x8EBC6AF09C88C6E3ULL;
static volatile uint64_t key_f = 0xC2B2AE3D27D4EB4FULL;

__declspec(noinline) static uint64_t rotl64(uint64_t value, unsigned count) {
    return (value << count) | (value >> (64 - count));
}

__declspec(noinline) static uint64_t rotr64(uint64_t value, unsigned count) {
    return (value >> count) | (value << (64 - count));
}

__declspec(noinline) uint64_t mix_payload(uint64_t x, uint64_t y) {
    uint64_t a = rotl64(x ^ key_a, 13);
    uint64_t b = y * key_b + key_c;
    uint64_t v = a + b;
    if ((x ^ y) & 0x20ULL) {
        v = rotl64(v ^ key_d, 17);
    } else {
        v = rotr64(v + key_e, 9);
    }
    return v ^ ((x + y) * key_f);
}

int main(int argc, char **argv) {
    char *end_x = 0, *end_y = 0;
    unsigned long long x, y;
    if (argc != 3) return 2;
    x = _strtoui64(argv[1], &end_x, 0);
    y = _strtoui64(argv[2], &end_y, 0);
    if (!end_x || !end_y || *end_x || *end_y) return 2;
    printf("%016llX\n", (unsigned long long)mix_payload((uint64_t)x, (uint64_t)y));
    return 0;
}
