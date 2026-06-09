// session.h
// Multi-client session management for the PQ-VPN server.
//
// ARCHITECTURE
// ------------
// Each connected client gets its own POSIX thread. The main thread
// handles authentication and spawns a worker thread per client.
// Each worker thread owns an independent session_t containing all
// per-client cryptographic state — keys, nonces, sequence numbers.
//
// This means:
//   - Multiple clients can be connected simultaneously
//   - A crash or disconnect on one client does not affect others
//   - Each client's crypto state is completely isolated
//
// Thread model:
//
//   main thread
//     │
//     ├── accept client 1 → authenticate → spawn thread_1 (session_1)
//     ├── accept client 2 → authenticate → spawn thread_2 (session_2)
//     └── accept client N → authenticate → spawn thread_N (session_N)
//
//   thread_1: KEM exchange → tunnel loop → cleanup → exit
//   thread_2: KEM exchange → tunnel loop → cleanup → exit
//
// SYNCHRONISATION
// ---------------
// The session table is protected by a single mutex. Threads only
// hold the mutex briefly when registering or removing themselves —
// never during crypto operations or I/O, which would serialise
// everything and defeat the purpose of threading.
//
// The TUN interface is shared across all sessions — all threads
// read from and write to the same tun_device_t. Linux TUN/TAP
// supports concurrent reads and writes safely.
//
// Depends on: pqc_common.h, pqc_cert.h, pthread

#ifndef SESSION_H
#define SESSION_H

#include "../common/pqc_common.h"
#include "../common/pqc_cert.h"
#include "tun.h"
#include "udp_support.h"

#include <pthread.h>
#include <netinet/in.h>
#include <stdatomic.h>

// ============================================================================
// LIMITS
// ============================================================================

// Maximum simultaneous connected clients.
// Each client holds ~AES_KEY_LEN + nonce state + buffers in its thread stack.
// 8 is reasonable for a research/demo deployment.
#define SESSION_MAX_CLIENTS   8

// ============================================================================
// SESSION STATE  (one per connected client)
// ============================================================================

// Session lifecycle states — used for clean shutdown signalling
typedef enum {
    SESSION_STATE_EMPTY      = 0,   // Slot is free
    SESSION_STATE_HANDSHAKE  = 1,   // Thread running KEM exchange
    SESSION_STATE_ACTIVE     = 2,   // Tunnel loop running
    SESSION_STATE_CLOSING    = 3,   // Disconnect in progress
} session_state_t;

typedef struct {
    // ---- Identity ----
    int                slot;            // Index in session_table
    struct sockaddr_in client_addr;     // Client's UDP address
    char               identity[CERT_IDENTITY_LEN]; // From client certificate

    // ---- Cryptographic state (per-client, never shared) ----
    uint8_t            session_key[AES_KEY_LEN];
    nonce_state_t      tx_nonce;
    uint64_t           tx_sequence;
    uint64_t           rx_expected;
    uint64_t           rx_bitmap;

    // ---- Session lifecycle ----
    session_state_t    state;
    volatile int       should_stop;     // Set to 1 to signal thread to exit
    pthread_t          thread;          // Thread handle

    // ---- Statistics ----
    uint64_t           pkts_sent;
    uint64_t           pkts_recv;
    uint64_t           keepalives_sent;
    uint64_t           keepalives_recv;
    uint64_t           bytes_sent;
    uint64_t           bytes_recv;
    uint64_t           replays_blocked;
    time_t             connected_at;
    time_t             last_rx_time;    // For idle timeout detection
} client_session_t;

// ============================================================================
// SESSION TABLE  (shared across all threads)
// ============================================================================

typedef struct {
    client_session_t   sessions[SESSION_MAX_CLIENTS];
    pthread_mutex_t    mutex;           // Protects sessions[] array
    int                count;           // Current active session count
    volatile int       server_running;  // Set to 0 to stop all threads

    // Shared server resources (read-only after init — no locking needed)
    tun_device_t      *tun;
    int                udp_sock;
    uint8_t            ca_pubkey[CERT_PUBKEY_LEN];
    pqc_cert_t        *server_cert;
} session_table_t;

// ============================================================================
// THREAD ARGUMENT
// ============================================================================

// Passed to each worker thread at spawn time.
// Contains everything the thread needs without accessing global state.
typedef struct {
    session_table_t  *table;
    int               slot;         // Which slot in table->sessions[]
} thread_arg_t;

// ============================================================================
// LIFECYCLE
// ============================================================================

// Initialise the session table before accepting any clients.
// Must be called once before session_accept_loop().
//
//   table       : table to initialise
//   tun         : shared TUN device (created before this call)
//   udp_sock    : shared UDP socket (bound before this call)
//   ca_pubkey   : CA public key for certificate verification
//   server_cert : server's own certificate (sent to clients)
//
// Returns 0 on success, -1 on failure.
int session_table_init(session_table_t  *table,
                       tun_device_t     *tun,
                       int               udp_sock,
                       const uint8_t     ca_pubkey[CERT_PUBKEY_LEN],
                       pqc_cert_t       *server_cert);

// Destroy the session table and free all resources.
// Signals all active threads to stop and waits for them to exit.
void session_table_destroy(session_table_t *table);

// ============================================================================
// CLIENT ACCEPTANCE
// ============================================================================

// Find a free slot in the session table.
// Returns slot index (0..SESSION_MAX_CLIENTS-1) or -1 if full.
// Caller must hold table->mutex.
int session_find_free_slot(session_table_t *table);

// Accept a new client and spawn a worker thread for it.
//
// This function:
//   1. Finds a free slot in the session table
//   2. Runs the ML-DSA-65 certificate handshake
//   3. If auth passes, initialises the session and spawns a thread
//   4. The thread runs the KEM exchange and tunnel loop
//
//   table       : session table
//   client_cert : client certificate received during auth (output)
//   client_addr : client's address (output)
//
// Returns slot index on success, -1 if table is full or auth failed.
int session_accept(session_table_t    *table,
                   pqc_cert_t         *client_cert,
                   struct sockaddr_in *client_addr);

// ============================================================================
// WORKER THREAD
// ============================================================================

// Worker thread entry point — runs KEM exchange then tunnel loop.
// Spawned by session_accept(). Cleans up and marks slot as EMPTY on exit.
// Do not call directly.
void *session_worker(void *arg);

// ============================================================================
// STATUS AND STATISTICS
// ============================================================================

// Print a summary of all active sessions to stdout.
// Safe to call from the main thread at any time.
void session_print_status(session_table_t *table);

// Print statistics for a single completed session.
void session_print_stats(const client_session_t *s);

// Return the number of currently active sessions.
// Acquires and releases mutex internally.
int session_count(session_table_t *table);

#endif // SESSION_H
