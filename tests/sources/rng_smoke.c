#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    unsigned int rand_r_seed = 0x12345678U;
    unsigned short nrand48_state[3] = {0x1111, 0x2222, 0x3333};
    unsigned short erand48_state[3] = {0x4444, 0x5555, 0x6666};
    unsigned short jrand48_state[3] = {0x7777, 0x8888, 0x9999};
    unsigned short seed48_state[3] = {0xaaaa, 0xbbbb, 0xcccc};
    unsigned short lcong48_state[7] = {1, 2, 3, 4, 5, 6, 7};
    struct random_data random_state = {0};
    char random_state_buffer[64] = {0};
    int32_t random_r_value = 0;
    int random_r_rc = 0;

    if (initstate_r(12345, random_state_buffer, sizeof(random_state_buffer), &random_state) != 0) {
        return 10;
    }

    srand(12345);
    srandom(12345);
    srand48(12345);
    printf("seed48_ptr=%p\n", (void *)seed48(seed48_state));
    lcong48(lcong48_state);

    printf("rand=%d\n", rand());
    printf("rand_r=%d seed=%u\n", rand_r(&rand_r_seed), rand_r_seed);
    printf("random=%ld\n", random());

    random_r_rc = random_r(&random_state, &random_r_value);
    printf("random_r=%d value=%d\n", random_r_rc, random_r_value);

    printf("lrand48=%ld\n", lrand48());
    printf(
        "nrand48=%ld state=%04x:%04x:%04x\n",
        nrand48(nrand48_state),
        nrand48_state[0],
        nrand48_state[1],
        nrand48_state[2]
    );
    printf("mrand48=%ld\n", mrand48());
    printf(
        "jrand48=%ld state=%04x:%04x:%04x\n",
        jrand48(jrand48_state),
        jrand48_state[0],
        jrand48_state[1],
        jrand48_state[2]
    );
    printf("drand48=%.17f\n", drand48());
    printf(
        "erand48=%.17f state=%04x:%04x:%04x\n",
        erand48(erand48_state),
        erand48_state[0],
        erand48_state[1],
        erand48_state[2]
    );
    return 0;
}
