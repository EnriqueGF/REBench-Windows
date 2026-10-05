#define _CRT_SECURE_NO_WARNINGS
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "payload.h"

#pragma section(".vmdat", read)
__declspec(allocate(".vmdat")) const unsigned char packed_cipher[CIPHER_LENGTH] = CIPHER_BYTES;
static const uint32_t tea_key[4] = KEY_WORDS;
static volatile uint32_t tea_nonce = NONCE;
static const uint64_t mix_keys[8] = MIX_KEYS;
static const uint64_t mix_salts[8] = MIX_SALTS;
static const unsigned char mix_rotations[8] = MIX_ROTATIONS;

static uint32_t rotl32(uint32_t value, unsigned bits) {
    return (value << bits) | (value >> (32 - bits));
}

static uint64_t rotl64(uint64_t value, unsigned bits) {
    return (value << bits) | (value >> (64 - bits));
}

__declspec(noinline) static void tea_block(uint32_t *v0, uint32_t *v1) {
    uint32_t x = *v0, y = *v1, sum = 0;
    for (unsigned round = 0; round < 32; ++round) {
        x += (((y << 4) ^ (y >> 5)) + y) ^ (sum + tea_key[sum & 3]);
        sum += 0x9E3779B9u;
        y += (((x << 4) ^ (x >> 5)) + x) ^ (sum + tea_key[(sum >> 11) & 3]);
    }
    *v0 = x;
    *v1 = y;
}

__declspec(noinline) static int unpack(unsigned char *program) {
    unsigned char packed[CIPHER_LENGTH];
    for (unsigned at = 0; at < CIPHER_LENGTH; at += 8) {
        uint32_t lo = tea_nonce ^ (at / 8), hi = (tea_nonce + at / 8) ^ 0xC17D83A5u;
        tea_block(&lo, &hi);
        unsigned char stream[8];
        memcpy(stream, &lo, 4);
        memcpy(stream + 4, &hi, 4);
        for (unsigned j = 0; j < 8 && at + j < CIPHER_LENGTH; ++j)
            packed[at + j] = packed_cipher[at + j] ^ stream[j];
    }
    unsigned src = 0, dst = 0;
    while (src < CIPHER_LENGTH) {
        unsigned token = packed[src++];
        if (token < 128) {
            unsigned count = token + 1;
            if (src + count > CIPHER_LENGTH || dst + count > PROGRAM_LENGTH) return 0;
            memcpy(program + dst, packed + src, count);
            src += count;
            dst += count;
        } else {
            unsigned count = (token & 127) + 3;
            if (src >= CIPHER_LENGTH || dst + count > PROGRAM_LENGTH) return 0;
            unsigned distance = packed[src++];
            if (!distance || distance > dst) return 0;
            for (unsigned i = 0; i < count; ++i) {
                program[dst] = program[dst - distance];
                ++dst;
            }
        }
    }
    return dst == PROGRAM_LENGTH;
}

__declspec(noinline) static int run_vm(const unsigned char *program, const unsigned char *input) {
    uint64_t state = STATE_INIT;
    unsigned char reg = 0;
    unsigned pc = 0, block = 0;
    while (pc < PROGRAM_LENGTH) {
        unsigned op = program[pc], arg = program[pc + 1];
        if (op == OP_CHECK) {
            uint64_t target;
            if (pc + 10 > PROGRAM_LENGTH || arg != block) return 0;
            memcpy(&target, program + pc + 2, 8);
            if (state != target) return 0;
            pc += 10;
            state = rotl64(target ^ RESET_KEY ^ (pc * RESET_MULTIPLIER), 9);
            ++block;
        } else {
            if (pc + 3 > PROGRAM_LENGTH) return 0;
            if (op == OP_LOAD) {
                if (arg >= INPUT_LENGTH) return 0;
                reg = input[arg];
            } else if (op == OP_MIX) {
                if (arg >= 8) return 0;
                state = rotl64((state ^ ((uint64_t)reg + mix_keys[arg])) * MIX_MULTIPLIER,
                               mix_rotations[arg]) + mix_salts[arg];
            } else if (op == OP_END) return pc + 3 == PROGRAM_LENGTH && block == 3 && arg == (state & 255);
            else return 0;
            pc += 3;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    unsigned char program[PROGRAM_LENGTH];
    if (argc != 2 || strlen(argv[1]) != INPUT_LENGTH || !unpack(program)) {
        puts("REJECT");
        return 1;
    }
    if (run_vm(program, (const unsigned char *)argv[1])) {
        puts("ACCEPT");
        return 0;
    }
    puts("REJECT");
    return 1;
}
