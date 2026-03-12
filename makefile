# Makefile for PQ-VPN
CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11 -D_POSIX_C_SOURCE=199309L
LDFLAGS = -loqs -lssl -lcrypto

# Directories
SRC_COMMON = src/common
SRC_VPN = src/vpn
BIN_DIR = bin

# Common source files
COMMON_SRC = $(SRC_COMMON)/pqc_common.c $(SRC_COMMON)/pqc_crypto.c

.PHONY: all clean test dirs help

all: dirs test_foundation

dirs:
	@mkdir -p $(BIN_DIR)

test_foundation: $(SRC_COMMON)/test_foundation.c $(COMMON_SRC)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $^ $(LDFLAGS)
	@echo "✅ Built: $(BIN_DIR)/test_foundation"

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
	@echo "  test             - Build and run tests"
	@echo "  clean            - Remove build artifacts"
	@echo "  help             - Show this help"
	@echo ""
	@echo "Example:"
	@echo "  make test        - Build and test foundation"
