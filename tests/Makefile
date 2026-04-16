CC = gcc

SRC_DIR := sources
BIN_DIR := bin
PATCHED_DIR := patched

COMMON_CFLAGS := -g -O0 -fno-pie -no-pie -Wall -Wextra
RETURN_CFLAGS := $(COMMON_CFLAGS) -fno-stack-protector -fno-omit-frame-pointer

BINARIES := \
	$(BIN_DIR)/entry_smoke \
	$(BIN_DIR)/return_restore \
	$(BIN_DIR)/rip_relative_entry

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

clean:
	$(RM) -r $(BIN_DIR) $(PATCHED_DIR)
