#include <string.h>

__attribute__((noinline))
int canary_helper(int value) {
    char buffer[32];
    memset(buffer, 0, sizeof(buffer));
    buffer[0] = (char)value;
    return buffer[0] + 1;
}

int main(void) {
    return canary_helper(40) == 41 ? 0 : 1;
}
