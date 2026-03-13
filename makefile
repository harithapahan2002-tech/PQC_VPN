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
VPN_SRC = $(SRC_VPN)/tun.c $(SRC_VPN)/udp_support.c

.PHONY: all clean test dirs help vpn

all: dirs test_foundation test_tun test_udp vpn

dirs:
	@mkdir -p $(BIN_DIR)

# Tests
test_foundation: $(SRC_COMMON)/test_foundation.c $(COMMON_SRC)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $^ $(LDFLAGS)
	@echo "✅ Built: $(BIN_DIR)/test_foundation"

test_tun: $(SRC_VPN)/test_tun.c $(SRC_VPN)/tun.c
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $^
	@echo "✅ Built: $(BIN_DIR)/test_tun"

test_udp: $(SRC_VPN)/test_udp.c $(COMMON_SRC) $(SRC_VPN)/udp_support.c
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $^ $(LDFLAGS)
	@echo "✅ Built: $(BIN_DIR)/test_udp"

# VPN programs
vpn: vpn_server vpn_client

vpn_server: $(SRC_VPN)/vpn_server.c $(COMMON_SRC) $(VPN_SRC)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $^ $(LDFLAGS)
	@echo "✅ Built: $(BIN_DIR)/vpn_server"

vpn_client: $(SRC_VPN)/vpn_client.c $(COMMON_SRC) $(VPN_SRC)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $^ $(LDFLAGS)
	@echo "✅ Built: $(BIN_DIR)/vpn_client"

test: test_foundation test_udp
	@echo ""
	@echo "Running foundation tests..."
	@$(BIN_DIR)/test_foundation
	@echo ""
	@echo "Running UDP tests..."
	@$(BIN_DIR)/test_udp

clean:
	rm -rf $(BIN_DIR)/* build/*
	@echo "🧹 Cleaned build artifacts"

help:
	@echo "PQ-VPN Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all              - Build everything (default)"
	@echo "  vpn              - Build VPN server and client"
	@echo "  test             - Run automated tests"
	@echo "  clean            - Remove build artifacts"
	@echo ""
	@echo "Usage:"
	@echo "  make vpn                           - Build VPN"
	@echo "  sudo bin/vpn_server                - Run server"
	@echo "  sudo bin/vpn_client                - Run client (another terminal)"