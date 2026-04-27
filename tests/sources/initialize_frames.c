#include <stdint.h>

__attribute__((noinline))
void dirty_stack(void) {
    volatile uint64_t slots[8];

    for (int i = 0; i < 8; i++) {
        slots[i] = 0x7f7f7f7f7f7f7f7fULL;
    }
}

__attribute__((noinline))
int frame_slot_is_zeroed(void) {
    volatile uint64_t slots[8];
    uint64_t observed;

    __asm__ volatile("movq -80(%%rbp), %0" : "=r"(observed));
    slots[0] = 1;
    return observed == 0 ? 0 : 1;
}

int main(void) {
    dirty_stack();
    return frame_slot_is_zeroed();
}
