#define _CRT_SECURE_NO_WARNINGS
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef VERSION
#define VERSION 1
#endif
#if VERSION == 1
#define TARGET_XOR 0xA35C7E19u
#define TARGET_ADD 0x174F2A03u
#elif VERSION == 2
#define TARGET_XOR 0xC1190B7Fu
#define TARGET_ADD 0x29AC5D11u
#elif VERSION == 3
#define TARGET_XOR 0x76E2845Du
#define TARGET_ADD 0xE13B6709u
#elif VERSION == 4
#define TARGET_XOR 0xF3A9814Bu
#define TARGET_ADD 0xD2410EA7u
#else
#error Unsupported version
#endif

typedef struct Context {
    unsigned char reserved[0x2A8];
    volatile uint32_t mode;
    uint32_t checksum;
} Context;

static volatile uint32_t runtime_value = 0x12345678u;

#if VERSION >= 2
__declspec(noinline) uint32_t relocated_helper_a(uint32_t x) {
    return (x * 0x1F123BB5u) ^ (x >> 11);
}
#endif
#if VERSION >= 3
__declspec(noinline) uint32_t relocated_helper_b(uint32_t x) {
    return (x ^ 0x7F4A7C15u) + (x << 5);
}
#endif

__declspec(noinline) uint32_t inspect_mode(Context *context) {
    uint32_t x = context->mode;
    x ^= TARGET_XOR;
    x += TARGET_ADD;
    return (x << 3) | (x >> 29);
}

/* Same structure field, deliberately different behavior. */
__declspec(noinline) uint32_t audit_decoy(Context *context) {
    uint32_t x = context->mode;
#if VERSION >= 2
    x ^= (x << 3) + 0x91E10DA5u;
#endif
#if VERSION >= 3
    x = (x * 0x27D4EB2Du) ^ (x >> 7);
#endif
#if VERSION >= 4
    x = (x + 0x4356D4A1u) ^ (x << 9);
#endif
    return (x * 7u) ^ 0x55AA3322u;
}

int main(int argc, char **argv) {
    Context context;
    uint32_t extra = 0;
    memset(&context, 0, sizeof(context));
    context.mode = runtime_value;
    if (argc > 1) context.mode = (uint32_t)strtoul(argv[1], 0, 0);
#if VERSION >= 2
    extra ^= relocated_helper_a(context.mode);
#endif
#if VERSION >= 3
    extra ^= relocated_helper_b(context.mode);
#endif
    printf("%08X\n", inspect_mode(&context) ^ audit_decoy(&context) ^ extra);
    return 0;
}
