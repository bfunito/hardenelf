#include <stdio.h>
#include <stdint.h>

__attribute__((noinline))
int tail_target(int value) {
    return value + 1;
}

__attribute__((noinline))
int tail_restore_target(int value) {
    return value + 1;
}

__attribute__((naked, noinline))
int direct_tail_helper(int value __attribute__((unused))) {
    __asm__(
        "push %rbp; mov %rsp, %rbp; pop %rbp; .byte 0xe9; "
        ".long tail_target - . - 4"
    );
}

__attribute__((naked, noinline))
int indirect_tail_helper(const char *message __attribute__((unused))) {
    __asm__("push %rbp; mov %rsp, %rbp; pop %rbp; jmp *puts@GOTPCREL(%rip)");
}

__attribute__((naked, noinline))
int corrupting_tail_helper(int value __attribute__((unused))) {
    __asm__(
        "push %rbp; mov %rsp, %rbp; movabs $0x4141414141414141, %rax; "
        "mov %rax, 8(%rbp); pop %rbp; .byte 0xe9; "
        ".long tail_restore_target - . - 4"
    );
}

int main(int argc, char **argv) {
    (void)argv;
    if (direct_tail_helper(40) != 41) {
        return 1;
    }
    if (indirect_tail_helper("tail-call-ok") < 0) {
        return 2;
    }
    return argc > 1 ? corrupting_tail_helper(40) : 0;
}
