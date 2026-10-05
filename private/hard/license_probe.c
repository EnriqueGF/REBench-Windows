#define _CRT_SECURE_NO_WARNINGS
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "license_payload.h"

/* The sample deliberately retains both current and retired validation paths. */
static volatile uint32_t current_seed = CURRENT_SEED;
static volatile uint32_t retired_seed = RETIRED_SEED;

__declspec(noinline) static uint32_t rotate32(uint32_t x, unsigned n) {
    return (x << n) | (x >> (32 - n));
}

__declspec(noinline) static unsigned char next_mask(uint32_t *state, unsigned index) {
    uint32_t x = *state;
    x ^= 0x9E3779B9u + index * 0x045D9F3Bu;
    x = rotate32(x, 7);
    x = x * 0x7FEB352Du + 0x846CA68Bu;
    *state = x;
    return (unsigned char)(x >> 23);
}

__declspec(noinline) static void decode_current(unsigned char *out) {
    uint32_t state = current_seed;
    for (unsigned i = 0; i < CODE_LENGTH; ++i) {
        out[i] = current_cipher[i] ^ next_mask(&state, i);
    }
}

__declspec(noinline) static void decode_retired(unsigned char *out) {
    uint32_t state = retired_seed;
    for (unsigned i = 0; i < CODE_LENGTH; ++i) {
        out[i] = retired_cipher[i] ^ next_mask(&state, i);
    }
}

__declspec(noinline) static int check_candidate(const char *candidate, int retired) {
    unsigned char decoded[CODE_LENGTH];
    unsigned difference = 0;
    if (strlen(candidate) != CODE_LENGTH) return 0;
    if (retired) decode_retired(decoded);
    else decode_current(decoded);
    for (unsigned i = 0; i < CODE_LENGTH; ++i) {
        difference |= (unsigned char)candidate[i] ^ decoded[i];
    }
    SecureZeroMemory(decoded, sizeof(decoded));
    return difference == 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && check_candidate(argv[1], 0)) {
        puts("ACCEPT");
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--retired") == 0 && check_candidate(argv[2], 1)) {
        puts("RETIRED ACCEPT");
        return 0;
    }
    puts("REJECT");
    return 1;
}
