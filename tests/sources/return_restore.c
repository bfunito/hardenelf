#include <stdint.h>

__attribute__((noinline))
int vulnerable(void) {
    uintptr_t *saved_return =
        (uintptr_t *)((char *)__builtin_frame_address(0) + sizeof(uintptr_t));
    *saved_return = 0x4141414141414141ULL;
    return 7;
}

int main(void) {
    return vulnerable() == 7 ? 0 : 1;
}
