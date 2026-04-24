CC = gcc

SRC_DIR := sources
BIN_DIR := bin
PATCHED_DIR := patched

COMMON_CFLAGS := -g -O0 -fno-pie -no-pie -Wall -Wextra
RETURN_CFLAGS := $(COMMON_CFLAGS) -fno-stack-protector -fno-omit-frame-pointer
RNG_CFLAGS := $(COMMON_CFLAGS) -D_GNU_SOURCE
PIE_CFLAGS := -g -O0 -fPIE -pie -Wall -Wextra
RETURN_PIE_CFLAGS := $(PIE_CFLAGS) -fno-stack-protector -fno-omit-frame-pointer
RNG_PIE_CFLAGS := $(PIE_CFLAGS) -D_GNU_SOURCE

BINARIES := \
	$(BIN_DIR)/entry_smoke \
	$(BIN_DIR)/return_restore \
	$(BIN_DIR)/rip_relative_entry \
	$(BIN_DIR)/rng_smoke \
	$(BIN_DIR)/entry_smoke_pie \
	$(BIN_DIR)/return_restore_pie \
	$(BIN_DIR)/rip_relative_entry_pie \
	$(BIN_DIR)/rng_smoke_pie

.PHONY: all clean

all: $(BINARIES) | $(PATCHED_DIR)

$(BIN_DIR) $(PATCHED_DIR):
	mkdir -p $@

$(BIN_DIR)/entry_smoke: $(SRC_DIR)/entry_smoke.c | $(BIN_DIR)
	$(CC) $(COMMON_CFLAGS) $< -o $@

$(BIN_DIR)/return_restore: $(SRC_DIR)/return_restore.c | $(BIN_DIR)
	$(CC) $(RETURN_CFLAGS) $< -o $@

$(BIN_DIR)/rip_relative_entry: $(SRC_DIR)/rip_relative_entry.c | $(BIN_DIR)
	$(CC) $(COMMON_CFLAGS) $< -o $@

$(BIN_DIR)/rng_smoke: $(SRC_DIR)/rng_smoke.c | $(BIN_DIR)
	$(CC) $(RNG_CFLAGS) $< -o $@

$(BIN_DIR)/entry_smoke_pie: $(SRC_DIR)/entry_smoke.c | $(BIN_DIR)
	$(CC) $(PIE_CFLAGS) $< -o $@

$(BIN_DIR)/return_restore_pie: $(SRC_DIR)/return_restore.c | $(BIN_DIR)
	$(CC) $(RETURN_PIE_CFLAGS) $< -o $@

$(BIN_DIR)/rip_relative_entry_pie: $(SRC_DIR)/rip_relative_entry.c | $(BIN_DIR)
	$(CC) $(PIE_CFLAGS) $< -o $@

$(BIN_DIR)/rng_smoke_pie: $(SRC_DIR)/rng_smoke.c | $(BIN_DIR)
	$(CC) $(RNG_PIE_CFLAGS) $< -o $@

clean:
	$(RM) -r $(BIN_DIR) $(PATCHED_DIR)
