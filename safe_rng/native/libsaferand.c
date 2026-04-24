#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/random.h>
#include <unistd.h>

static unsigned short g_seed48_state[3] = {0x330e, 0xabcd, 0x1234};

static void fill_random_bytes(void *buffer, size_t size) {
    unsigned char *cursor = (unsigned char *)buffer;

    while (size > 0) {
        ssize_t received = getrandom(cursor, size, 0);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            abort();
        }
        cursor += (size_t)received;
        size -= (size_t)received;
    }
}

static uint32_t random_u32(void) {
    uint32_t value = 0;
    fill_random_bytes(&value, sizeof(value));
    return value;
}

static uint64_t random_u64(void) {
    uint64_t value = 0;
    fill_random_bytes(&value, sizeof(value));
    return value;
}

static uint32_t random_31_bits(void) {
    return random_u32() & 0x7fffffffU;
}

static uint64_t random_48_bits(void) {
    return random_u64() & 0x0000ffffffffffffULL;
}

static double random_unit_interval(void) {
    return (double)(random_u64() >> 11) * (1.0 / 9007199254740992.0);
}

static void write_state48(unsigned short state[3], uint64_t value) {
    if (state == NULL) {
        return;
    }

    state[0] = (unsigned short)(value & 0xffffU);
    state[1] = (unsigned short)((value >> 16) & 0xffffU);
    state[2] = (unsigned short)((value >> 32) & 0xffffU);
}

int saferand_rand(void) {
    return (int)random_31_bits();
}

int rand(void) {
    return saferand_rand();
}

int saferand_rand_r(unsigned int *seedp) {
    uint32_t value = random_u32();
    if (seedp != NULL) {
        *seedp = value;
    }
    return (int)(value & 0x7fffffffU);
}

int rand_r(unsigned int *seedp) {
    return saferand_rand_r(seedp);
}

long saferand_random(void) {
    return (long)random_31_bits();
}

long random(void) {
    return saferand_random();
}

int saferand_random_r(struct random_data *buf, int32_t *result) {
    if (buf == NULL || result == NULL) {
        errno = EINVAL;
        return -1;
    }

    (void)buf;
    *result = (int32_t)random_31_bits();
    return 0;
}

int random_r(struct random_data *buf, int32_t *result) {
    return saferand_random_r(buf, result);
}

long saferand_lrand48(void) {
    return (long)random_31_bits();
}

long lrand48(void) {
    return saferand_lrand48();
}

long saferand_nrand48(unsigned short xsubi[3]) {
    uint64_t state = random_48_bits();
    write_state48(xsubi, state);
    return (long)(state >> 17);
}

long nrand48(unsigned short xsubi[3]) {
    return saferand_nrand48(xsubi);
}

long saferand_mrand48(void) {
    return (long)(int32_t)random_u32();
}

long mrand48(void) {
    return saferand_mrand48();
}

long saferand_jrand48(unsigned short xsubi[3]) {
    uint64_t state = random_48_bits();
    write_state48(xsubi, state);
    return (long)(int32_t)(state >> 16);
}

long jrand48(unsigned short xsubi[3]) {
    return saferand_jrand48(xsubi);
}

double saferand_drand48(void) {
    return random_unit_interval();
}

double drand48(void) {
    return saferand_drand48();
}

double saferand_erand48(unsigned short xsubi[3]) {
    uint64_t state = random_48_bits();
    write_state48(xsubi, state);
    return (double)state / 281474976710656.0;
}

double erand48(unsigned short xsubi[3]) {
    return saferand_erand48(xsubi);
}

void saferand_srand(unsigned int seed) {
    (void)seed;
}

void srand(unsigned int seed) {
    saferand_srand(seed);
}

void saferand_srandom(unsigned int seed) {
    (void)seed;
}

void srandom(unsigned int seed) {
    saferand_srandom(seed);
}

void saferand_srand48(long int seedval) {
    (void)seedval;
}

void srand48(long int seedval) {
    saferand_srand48(seedval);
}

unsigned short *saferand_seed48(unsigned short seed16v[3]) {
    (void)seed16v;
    return g_seed48_state;
}

unsigned short *seed48(unsigned short seed16v[3]) {
    return saferand_seed48(seed16v);
}

void saferand_lcong48(unsigned short param[7]) {
    (void)param;
}

void lcong48(unsigned short param[7]) {
    saferand_lcong48(param);
}
