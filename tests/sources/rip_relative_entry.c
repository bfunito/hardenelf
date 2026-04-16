int global_value = 40;

__attribute__((naked, noinline))
int rip_relative_entry(void) {
    __asm__(
        "mov global_value(%rip), %eax\n"
        "add $1, %eax\n"
        "add $1, %eax\n"
        "ret\n"
    );
}

int main(void) {
    return rip_relative_entry() == 42 ? 0 : 1;
}
