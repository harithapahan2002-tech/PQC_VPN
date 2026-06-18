# Makefile
# PQ-VPN build system
#
# Targets:
#   make all          — build vpn_server, vpn_client, gen_psk, gen_ca, gen_cert
#   make tests        — build and run all test suites
#   make test_foundation
#   make test_auth
#   make test_replay
#   make test_cert
#   make clean        — remove all build artefacts
#
# Dependencies:
#   liboqs   — Open Quantum Safe library (ML-KEM-768, ML-DSA-65)
#   openssl  — libssl + libcrypto (AES-GCM, HMAC, HKDF, RAND)
#
# Install dependencies (Ubuntu/Debian):
#   sudo apt install libssl-dev
#   # liboqs: build from source — https://github.com/open-quantum-safe/liboqs
#
# First-time setup with ML-DSA certificates:
#   make all
#   sudo ./bin/gen_ca               — generate CA keypair (once ever)
#   sudo ./bin/gen_cert server      — issue server certificate
#   sudo ./bin/gen_cert client      — issue client certificate
#   Copy ca_cert.pub to both machines
#   sudo ./bin/vpn_server
#   sudo ./bin/vpn_client

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
SRC_BENCH   := src/bench
BIN_DIR     := bin
OBJ_DIR     := obj

INCLUDES    := -I$(SRC_COMMON) -I$(SRC_VPN)

# ============================================================================
# LIBRARIES
# ============================================================================

LIBOQS_PREFIX ?= /usr/local

LIBOQS_INC  := -I$(LIBOQS_PREFIX)/include
LIBOQS_LIB  := -L$(LIBOQS_PREFIX)/lib -loqs

OPENSSL_LIB := -lssl -lcrypto

LIBS        := $(LIBOQS_LIB) $(OPENSSL_LIB) -lpthread

# ============================================================================
# SOURCE FILES
# ============================================================================

# Common layer — compiled into every target that needs it
# pqc_cert.c added for ML-DSA-65 certificate authentication
COMMON_SRCS := $(SRC_COMMON)/pqc_common.c \
               $(SRC_COMMON)/pqc_crypto.c \
               $(SRC_COMMON)/pqc_auth.c   \
               $(SRC_COMMON)/pqc_cert.c

# VPN network layer
VPN_SRCS    := $(SRC_VPN)/tun.c \
               $(SRC_VPN)/udp_support.c \
               $(SRC_VPN)/session.c

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
        test_foundation test_auth test_replay test_cert \
        bench \
        dirs

all: dirs \
     $(BIN_DIR)/vpn_server \
     $(BIN_DIR)/vpn_client \
     $(BIN_DIR)/gen_psk    \
     $(BIN_DIR)/gen_ca     \
     $(BIN_DIR)/gen_cert

dirs:
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(OBJ_DIR)/common
	@mkdir -p $(OBJ_DIR)/vpn
	@mkdir -p $(OBJ_DIR)/tests
	@mkdir -p $(OBJ_DIR)/bench

# ----------------------------------------------------------------------------
# Object compilation
# ----------------------------------------------------------------------------

$(OBJ_DIR)/common/%.o: $(SRC_COMMON)/%.c | dirs
	@echo "  CC  $<"
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBOQS_INC) -c $< -o $@

$(OBJ_DIR)/vpn/%.o: $(SRC_VPN)/%.c | dirs
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
# PSK generator (legacy — kept for reference and test_auth.c)
# ----------------------------------------------------------------------------

$(BIN_DIR)/gen_psk: dirs $(COMMON_OBJS) $(SRC_COMMON)/gen_psk_main.c
	@echo "  LD  $@"
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBOQS_INC) \
	    $(COMMON_OBJS) $(SRC_COMMON)/gen_psk_main.c \
	    $(LIBS) -o $@
	@echo "  ✅  Built $@"

# ----------------------------------------------------------------------------
# CA keypair generator
# Run once ever: sudo ./bin/gen_ca
# Writes ca_key.priv (secret) and ca_cert.pub (distribute to all peers)
# ----------------------------------------------------------------------------

$(BIN_DIR)/gen_ca: dirs $(COMMON_OBJS) $(SRC_COMMON)/gen_ca_main.c
	@echo "  LD  $@"
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBOQS_INC) \
	    $(COMMON_OBJS) $(SRC_COMMON)/gen_ca_main.c \
	    $(LIBS) -o $@
	@echo "  ✅  Built $@"

# ----------------------------------------------------------------------------
# Certificate issuance tool
# Run once per identity:
#   sudo ./bin/gen_cert server   → server_cert.bin + server_key.priv
#   sudo ./bin/gen_cert client   → client_cert.bin + client_key.priv
# ----------------------------------------------------------------------------

$(BIN_DIR)/gen_cert: dirs $(COMMON_OBJS) $(SRC_COMMON)/gen_cert_main.c
	@echo "  LD  $@"
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBOQS_INC) \
	    $(COMMON_OBJS) $(SRC_COMMON)/gen_cert_main.c \
	    $(LIBS) -o $@
	@echo "  ✅  Built $@"

# ----------------------------------------------------------------------------
# Tests
# ----------------------------------------------------------------------------

test_foundation: dirs $(COMMON_OBJS)
	@echo "  LD  $(BIN_DIR)/test_foundation"
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBOQS_INC) \
	    $(COMMON_OBJS) $(SRC_TESTS)/test_foundation.c \
	    $(LIBS) -o $(BIN_DIR)/test_foundation
	@echo "  RUN $(BIN_DIR)/test_foundation"
	@$(BIN_DIR)/test_foundation

test_auth: dirs $(COMMON_OBJS)
	@echo "  LD  $(BIN_DIR)/test_auth"
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBOQS_INC) \
	    $(COMMON_OBJS) $(SRC_TESTS)/test_auth.c \
	    $(LIBS) -o $(BIN_DIR)/test_auth
	@echo "  RUN $(BIN_DIR)/test_auth"
	@$(BIN_DIR)/test_auth

test_replay: dirs $(COMMON_OBJS)
	@echo "  LD  $(BIN_DIR)/test_replay"
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBOQS_INC) \
	    $(COMMON_OBJS) $(SRC_TESTS)/test_replay.c \
	    $(LIBS) -o $(BIN_DIR)/test_replay
	@echo "  RUN $(BIN_DIR)/test_replay"
	@$(BIN_DIR)/test_replay

# test_cert needs liboqs (ML-DSA signing/verification)
test_cert: dirs $(COMMON_OBJS)
	@echo "  LD  $(BIN_DIR)/test_cert"
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBOQS_INC) \
	    $(COMMON_OBJS) $(SRC_TESTS)/test_cert.c \
	    $(LIBS) -o $(BIN_DIR)/test_cert
	@echo "  RUN $(BIN_DIR)/test_cert"
	@$(BIN_DIR)/test_cert

tests: test_foundation test_auth test_replay test_cert
	@echo ""
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "  All test suites completed"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ----------------------------------------------------------------------------
# Benchmark suite — standalone, does not depend on VPN core objects
# Compares ML-KEM-768/ML-DSA-65 against X25519/ECDSA-P256, plus
# AES-256-GCM throughput at varying packet sizes.
#
# Usage:
#   make bench
#   ./bin/bench_crypto --tag local
#   ./bin/bench_crypto --tag cloud --output cloud_results.csv
# ----------------------------------------------------------------------------

BENCH_OBJS := $(OBJ_DIR)/bench/bench_common.o \
              $(OBJ_DIR)/bench/bench_kem.o    \
              $(OBJ_DIR)/bench/bench_sig.o    \
              $(OBJ_DIR)/bench/bench_aead.o

$(OBJ_DIR)/bench/%.o: $(SRC_BENCH)/%.c | dirs
	@echo "  CC  $<"
	$(CC) $(CFLAGS) -I$(SRC_BENCH) $(LIBOQS_INC) -c $< -o $@

$(BIN_DIR)/bench_crypto: dirs $(BENCH_OBJS) $(SRC_BENCH)/bench_main.c
	@echo "  LD  $@"
	$(CC) $(CFLAGS) -I$(SRC_BENCH) $(LIBOQS_INC) \
	    $(BENCH_OBJS) $(SRC_BENCH)/bench_main.c \
	    $(LIBS) -lm -o $@
	@echo "  ✅  Built $@"

bench: $(BIN_DIR)/bench_crypto
	@echo "  RUN $(BIN_DIR)/bench_crypto"
	@./$(BIN_DIR)/bench_crypto --tag local

# ----------------------------------------------------------------------------
# Clean
# ----------------------------------------------------------------------------

clean:
	@echo "  CLEAN"
	rm -rf $(BIN_DIR) $(OBJ_DIR)
	@echo "  ✅  Clean complete"
