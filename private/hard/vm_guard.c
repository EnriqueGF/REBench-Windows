#define _CRT_SECURE_NO_WARNINGS
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "vm_payload.h"

#pragma section(".vmz", read)
__declspec(allocate(".vmz")) const unsigned char encoded_program[PROGRAM_LENGTH] = PROGRAM_BYTES;
static volatile unsigned char mask_seed = MASK_SEED;

__declspec(noinline) static void unpack_program(unsigned char *plain) {
    unsigned char mask = mask_seed;
    for (unsigned i = 0; i < PROGRAM_LENGTH; ++i) {
        mask = (unsigned char)(mask * 73u + 41u);
        plain[i] = encoded_program[i] ^ mask;
    }
}

__declspec(noinline) static int execute_program(const unsigned char *program, const char *input) {
    unsigned char reg = 0;
    unsigned pc = 0;
    while (pc + 2 < PROGRAM_LENGTH) {
        unsigned char op = program[pc];
        unsigned char arg = program[pc + 1];
        pc += 3;
        switch (op) {
        case 0x31: reg = (unsigned char)input[arg]; break;
        case 0xA4: reg ^= arg; break;
        case 0x5B: reg = (unsigned char)((reg << arg) | (reg >> (8 - arg))); break;
        case 0x79: reg = (unsigned char)(reg + arg); break;
        case 0xC2: if (reg != arg) return 0; break;
        case 0x0D: break;
        case 0xF0: return 1;
        default: return 0;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    unsigned char decoded[PROGRAM_LENGTH];
    if (argc != 2 || strlen(argv[1]) != INPUT_LENGTH) {
        puts("REJECT");
        return 1;
    }
    unpack_program(decoded);
    if (execute_program(decoded, argv[1])) {
        puts("ACCEPT");
        return 0;
    }
    puts("REJECT");
    return 1;
}
