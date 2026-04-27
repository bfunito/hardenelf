#include <printf.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

static const char null_format_message[] = "format string pointer is null\n";
static const char underflow_message[] = "format string argument underflow\n";

size_t count_format(const char *fmt) {
    if (fmt == NULL) {
        return SIZE_MAX;
    }

    return parse_printf_format(fmt, 0, NULL);
}

void check_format(const char *fmt, size_t n_variadic) {
    size_t required = count_format(fmt);

    if (required == SIZE_MAX) {
        (void)write(STDERR_FILENO, null_format_message, sizeof(null_format_message) - 1);
        abort();
    }

    if (required > n_variadic) {
        (void)write(STDERR_FILENO, underflow_message, sizeof(underflow_message) - 1);
        abort();
    }
}
