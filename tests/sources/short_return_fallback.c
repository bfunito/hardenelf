#include <stdlib.h>

__asm__(
    ".text\n"
    ".globl short_return_helper\n"
    ".type short_return_helper, @function\n"
    "short_return_helper:\n"
    "push %rbp\n"
    "mov %rsp, %rbp\n"
    "push %rbx\n"
    "mov %edi, %ebx\n"
    "lea 1(%rbx), %eax\n"
    "movabs $0x4141414141414141, %rcx\n"
    "mov %rcx, 8(%rbp)\n"
    "mov -8(%rbp), %rbx\n"
    "cmp %eax, %eax\n"
    "je 1f\n"
    "call abort@PLT\n"
    "1:\n"
    "leave\n"
    "ret\n"
    ".size short_return_helper, .-short_return_helper\n"
    ".balign 128\n"
    ".rept 16\n"
    "nop\n"
    ".endr\n"
);

int short_return_helper(int value);

int main(void) {
    return short_return_helper(40) == 41 ? 0 : 1;
}
