#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int dynamic_format(const char *fmt) {
    printf(fmt);
    return 0;
}

static int one_arg_format(const char *fmt) {
    printf(fmt, 111);
    return 0;
}

static int width_precision_format(void) {
    printf("%*.*s\n", 6, 3, "abcdef");
    return 0;
}

static int missing_star_format(const char *fmt) {
    printf(fmt, 6);
    return 0;
}

static int floating_format(void) {
    printf("%.2f\n", 3.25);
    return 0;
}

static int many_args_format(void) {
    printf("%d %d %d %d %d %d %d %d\n", 1, 2, 3, 4, 5, 6, 7, 8);
    return 0;
}

static int fprintf_dynamic_format(const char *fmt) {
    fprintf(stdout, fmt);
    return 0;
}

static int snprintf_format(void) {
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%d:%s:%%\n", 7, "ok");
    fputs(buffer, stdout);
    return 0;
}

static int sprintf_format(void) {
    char buffer[64];
    sprintf(buffer, "%s:%d\n", "value", 9);
    fputs(buffer, stdout);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return 2;
    }

    if (strcmp(argv[1], "dynamic") == 0 && argc >= 3) {
        return dynamic_format(argv[2]);
    }
    if (strcmp(argv[1], "one") == 0 && argc >= 3) {
        return one_arg_format(argv[2]);
    }
    if (strcmp(argv[1], "width") == 0) {
        return width_precision_format();
    }
    if (strcmp(argv[1], "width-missing") == 0 && argc >= 3) {
        return missing_star_format(argv[2]);
    }
    if (strcmp(argv[1], "float") == 0) {
        return floating_format();
    }
    if (strcmp(argv[1], "many") == 0) {
        return many_args_format();
    }
    if (strcmp(argv[1], "fprintf-dynamic") == 0 && argc >= 3) {
        return fprintf_dynamic_format(argv[2]);
    }
    if (strcmp(argv[1], "snprintf") == 0) {
        return snprintf_format();
    }
    if (strcmp(argv[1], "sprintf") == 0) {
        return sprintf_format();
    }

    return 2;
}
