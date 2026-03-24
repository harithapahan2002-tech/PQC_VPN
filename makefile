# Makefile
# PQ-VPN build system
#
# Targets:
#   make all          — build vpn_server, vpn_client, gen_psk, and all tests
#   make vpn_server   — build server only
#   make vpn_client   — build client only
#   make gen_psk      — build PSK generator utility
#   make tests        — build and run all test suites
#   make test_foundation
#   make test_auth
#   make test_replay
#   make clean        — remove all build artefacts
#
# Dependencies:
#   liboqs   — Open Quantum Safe library (ML-KEM-768)
#   openssl  — libssl + libcrypto (AES-GCM, HMAC, HKDF, RAND)
#
# Install dependencies (Ubuntu/Debian):
#   sudo apt install libssl-dev
#   # liboqs: build from source — https://github.com/open-quantum-safe/liboqs
#
# Usage after build:
#   1. Generate a shared PSK:   sudo ./bin/gen_psk
#   2. Copy psk.conf to client machine
#   3. Start server:            sudo ./bin/vpn_server
#   4. Start client:            sudo ./bin/vpn_client

# ============================================================================
# COMPILER AND FLAGS
# ============================================================================

CC      := gcc
CFLAGS  := -std=c11 -Wall -Wextra -Wpedantic \
           -Wformat=2 -Wstrict-prototypes \
           -fstack-protector-strong \
           -D_POSIX_C_SOURCE=200809L

# Debug build (default): symbols + sanitisers
CFLAGS  += -g -O0 \
           -fsanitize=address,undefined \
           -fno-omit-frame-pointer

# Release build: uncomment these and comment out the debug block above
# CFLAGS  += -O2 -DNDEBUG

# ============================================================================
# PATHS
# ============================================================================

SRC_COMMON  := src/common
SRC_VPN     := src/vpn
SRC_TESTS   := src/tests
BIN_DIR     := bin
OBJ_DIR     := obj

# Include paths
INCLUDES    := -I$(SRC_COMMON) -I$(SRC_VPN)

# ============================================================================
# LIBRARIES
# ============================================================================

# liboqs — adjust prefix if installed to a non-standard location
# Default: /usr/local (from a source build)
# Override: make LIBOQS_PREFIX=/opt/liboqs
LIBOQS_PREFIX ?= /usr/local

LIBOQS_INC  := -I$(LIBOQS_PREFIX)/include
LIBOQS_LIB  := -L$(LIBOQS_PREFIX)/lib -loqs

OPENSSL_LIB := -lssl -lcrypto

LIBS        := $(LIBOQS_LIB) $(OPENSSL_LIB) -lpthread

# ============================================================================
# SOURCE FILES
# ============================================================================

# Common layer — compiled into every target that needs it
COMMON_SRCS := $(SRC_COMMON)/pqc_common.c \
               $(SRC_COMMON)/pqc_crypto.c \
               $(SRC_COMMON)/pqc_auth.c

# VPN network layer
VPN_SRCS    := $(SRC_VPN)/tun.c \
               $(SRC_VPN)/udp_support.c

# All shared sources (common + network)
SHARED_SRCS := $(COMMON_SRCS) $(VPN_SRCS)

# ============================================================================
# OBJECT FILES
# ============================================================================

COMMON_OBJS := $(patsubst $(SRC_COMMON)/%.c, $(OBJ_DIR)/common/%.o, $(COMMON_SRCS))
VPN_OBJS    := $(patsubst $(SRC_VPN)/%.c,    $(OBJ_DIR)/vpn/%.o,    $(VPN_SRCS))
SHARED_OBJS := $(COMMON_OBJS) $(VPN_OBJS)

# ============================================================================
# TARGETS
# ============================================================================

.PHONY: all clean tests \
        test_foundation test_auth test_replay \
        run_tests dirs

all: dirs $(BIN_DIR)/vpn_server $(BIN_DIR)/vpn_client $(BIN_DIR)/gen_psk

# Create output directories
dirs:
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(OBJ_DIR)/common
	@mkdir -p $(OBJ_DIR)/vpn
	@mkdir -p $(OBJ_DIR)/tests

# ----------------------------------------------------------------------------
# Common object compilation
# ----------------------------------------------------------------------------

$(OBJ_DIR)/common/%.o: $(SRC_COMMON)/%.c
	@echo "  CC  $<"
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBOQS_INC) -c $< -o $@

$(OBJ_DIR)/vpn/%.o: $(SRC_VPN)/%.c
	@echo "  CC  $<"
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBOQS_INC) -c $< -o $@

# ----------------------------------------------------------------------------
# VPN server
# ----------------------------------------------------------------------------

$(BIN_DIR)/vpn_server: $(SHARED_OBJS) $(SRC_VPN)/vpn_server.c
	@echo "  LD  $@"
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBOQS_INC) \
	    $(SHARED_OBJS) $(SRC_VPN)/vpn_server.c \
	    $(LIBS) -o $@
	@echo "  ✅  Built $@"

# ----------------------------------------------------------------------------
# VPN client
# ----------------------------------------------------------------------------

$(BIN_DIR)/vpn_client: $(SHARED_OBJS) $(SRC_VPN)/vpn_client.c
	@echo "  LD  $@"
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBOQS_INC) \
	    $(SHARED_OBJS) $(SRC_VPN)/vpn_client.c \
	    $(LIBS) -o $@
	@echo "  ✅  Built $@"

# ----------------------------------------------------------------------------
# PSK generator utility
# Thin wrapper around auth_generate_psk_file() — no TUN or liboqs needed
# ----------------------------------------------------------------------------

$(BIN_DIR)/gen_psk: dirs $(COMMON_OBJS) $(SRC_COMMON)/gen_psk_main.c
	@echo "  LD  $@"
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBOQS_INC) \
	    $(COMMON_OBJS) $(SRC_COMMON)/gen_psk_main.c \
	    $(OPENSSL_LIB) -o $@
	@echo "  ✅  Built $@"

# ----------------------------------------------------------------------------
# Test: foundation (HKDF, nonce, AES-GCM, I/O)
# Does not need liboqs or TUN — common layer only
# ----------------------------------------------------------------------------

test_foundation: dirs $(COMMON_OBJS)
	@echo "  LD  $(BIN_DIR)/test_foundation"
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBOQS_INC) \
	    $(COMMON_OBJS) $(SRC_TESTS)/test_foundation.c \
	    $(OPENSSL_LIB) -o $(BIN_DIR)/test_foundation
	@echo "  RUN $(BIN_DIR)/test_foundation"
	@$(BIN_DIR)/test_foundation

# ----------------------------------------------------------------------------
# Test: auth (PSK loading, key derivation, MAC properties)
# ----------------------------------------------------------------------------

test_auth: dirs $(COMMON_OBJS)
	@echo "  LD  $(BIN_DIR)/test_auth"
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBOQS_INC) \
	    $(COMMON_OBJS) $(SRC_TESTS)/test_auth.c \
	    $(OPENSSL_LIB) -o $(BIN_DIR)/test_auth
	@echo "  RUN $(BIN_DIR)/test_auth"
	@$(BIN_DIR)/test_auth

# ----------------------------------------------------------------------------
# Test: replay protection (sequence window, bitmap, forward jump rejection)
# ----------------------------------------------------------------------------

test_replay: dirs $(COMMON_OBJS)
	@echo "  LD  $(BIN_DIR)/test_replay"
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBOQS_INC) \
	    $(COMMON_OBJS) $(SRC_TESTS)/test_replay.c \
	    $(OPENSSL_LIB) -o $(BIN_DIR)/test_replay
	@echo "  RUN $(BIN_DIR)/test_replay"
	@$(BIN_DIR)/test_replay

# ----------------------------------------------------------------------------
# Run all tests
# ----------------------------------------------------------------------------

tests: test_foundation test_auth test_replay
	@echo ""
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "  All test suites completed"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ----------------------------------------------------------------------------
# Clean
# ----------------------------------------------------------------------------

clean:
	@echo "  CLEAN"
	rm -rf $(BIN_DIR) $(OBJ_DIR)
	@echo "  ✅  Clean complete"