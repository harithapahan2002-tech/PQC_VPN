# Makefile for PQ-VPN
CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11 -D_POSIX_C_SOURCE=200809L
LDFLAGS = -loqs -lssl -lcrypto

# Directories
SRC_COMMON = src/common
SRC_VPN = src/vpn
BIN_DIR = bin

# Common source files
COMMON_SRC = $(SRC_COMMON)/pqc_common.c $(SRC_COMMON)/pqc_crypto.c

# VPN source files
VPN_SRC = $(SRC_VPN)/tun.c

.PHONY: all clean test dirs help

all: dirs test_foundation test_tun

dirs:
	@mkdir -p $(BIN_DIR)

test_foundation: $(SRC_COMMON)/test_foundation.c $(COMMON_SRC)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $^ $(LDFLAGS)
	@echo "✅ Built: $(BIN_DIR)/test_foundation"

test_tun: $(SRC_VPN)/test_tun.c $(VPN_SRC)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $^
	@echo "✅ Built: $(BIN_DIR)/test_tun"

test: test_foundation
	@echo "Running foundation tests..."
	@$(BIN_DIR)/test_foundation

clean:
	rm -rf $(BIN_DIR)/* build/*
	@echo "🧹 Cleaned build artifacts"

help:
	@echo "PQ-VPN Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all              - Build everything (default)"
	@echo "  test             - Build and run foundation tests"
	@echo "  test_foundation  - Build foundation test only"
	@echo "  test_tun         - Build TUN test only"
	@echo "  clean            - Remove build artifacts"
	@echo "  help             - Show this help"
	@echo ""
	@echo "Usage:"
	@echo "  make all         - Build all tests"
	@echo "  make test        - Run foundation tests"
	@echo "  sudo make test_tun && sudo bin/test_tun  - Test TUN"