#include <stdint.h>
#include <stdio.h>

extern uint64_t unwind_target(uint64_t x, uint64_t y);

int main(void) {
    printf("%016llX\n", (unsigned long long)unwind_target(0x1234, 0x5678));
    return 0;
}
