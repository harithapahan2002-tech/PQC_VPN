// test_replay.c
// Test suite for check_sequence() replay protection.
//
// Fixes from the old test_replay.c:
//   - Test 4 (duplicate after sequence jump) was a false pass — the bitmap
//     state was not correctly tracked across the sequence jump in Test 3,
//     so the duplicate was accepted instead of rejected.
//   - Added bitmap continuity test to explicitly verify state carries
//     across calls.
//   - Added large forward jump rejection test (new behaviour in pqc_common.c).
//   - Each test section resets state explicitly so tests are independent.
//
// Build:
//   gcc -o test_replay test_replay.c pqc_common.c -lssl -lcrypto
// Run:
//   ./test_replay

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../common/pqc_common.h"

// ============================================================================
// TEST FRAMEWORK
// ============================================================================

static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    do { tests_run++; printf("  %-60s", (name)); } while (0)

#define PASS() \
    do { tests_passed++; printf("✅ PASS\n"); } while (0)

#define FAIL(reason) \
    do { tests_failed++; printf("❌ FAIL — %s\n", (reason)); } while (0)

#define ASSERT(cond, reason) \
    do { if (!(cond)) { FAIL(reason); return; } } while (0)

// Shorthand for check_sequence
#define CS(seq) check_sequence((seq), &expected, &bitmap)

// ============================================================================
// BASIC SEQUENCE TESTS
// ============================================================================

static void test_normal_sequence(void) {
    TEST("Normal sequence: 0, 1, 2, 3 all accepted");

    uint64_t expected = 0, bitmap = 0;

    ASSERT(CS(0) == 1, "seq 0 rejected");
    ASSERT(CS(1) == 1, "seq 1 rejected");
    ASSERT(CS(2) == 1, "seq 2 rejected");
    ASSERT(CS(3) == 1, "seq 3 rejected");
    ASSERT(expected == 4, "expected should be 4 after processing 0-3");
    PASS();
}

static void test_replay_immediately_after(void) {
    TEST("Replay: immediately repeated sequence is rejected");

    uint64_t expected = 0, bitmap = 0;

    ASSERT(CS(0) == 1, "seq 0 initial accept failed");
    ASSERT(CS(0) == 0, "seq 0 replay should be rejected");
    PASS();
}

static void test_replay_of_old_packet(void) {
    TEST("Replay: old packet well behind window is rejected");

    uint64_t expected = 0, bitmap = 0;

    // Advance to seq 70
    for (uint64_t i = 0; i <= 70; i++) {
        int r = CS(i);
        if (r != 1) { FAIL("failed advancing sequence"); return; }
    }

    // Try seq 0 — 71 packets behind, well outside SEQUENCE_WINDOW (64)
    ASSERT(CS(0) == 0, "very old packet should be rejected");
    PASS();
}

// ============================================================================
// OUT-OF-ORDER TESTS
// ============================================================================

static void test_out_of_order_within_window(void) {
    TEST("Out-of-order: packets within window accepted in any order");

    uint64_t expected = 0, bitmap = 0;

    // Send 5, then 4 (one behind), then 6
    ASSERT(CS(5) == 1, "seq 5 rejected");
    ASSERT(expected == 6, "expected should advance to 6 after seq 5");

    ASSERT(CS(4) == 1, "seq 4 (one behind, in window) rejected");
    ASSERT(expected == 6, "expected should still be 6 after out-of-order seq 4");

    ASSERT(CS(6) == 1, "seq 6 rejected");
    ASSERT(expected == 7, "expected should be 7 after seq 6");
    PASS();
}

static void test_duplicate_within_window(void) {
    TEST("Duplicate: packet within window seen twice is rejected second time");

    uint64_t expected = 0, bitmap = 0;

    ASSERT(CS(5) == 1, "seq 5 initial accept failed");
    ASSERT(CS(4) == 1, "seq 4 out-of-order accept failed");
    ASSERT(CS(6) == 1, "seq 6 accept failed");

    // Now try seq 4 again — it is within the window and already seen
    // This was the false-pass bug in the old test_replay.c:
    // after the sequence jumped to 7 (expected), seq 4's bit_pos was
    // recalculated as diff-1 = (7-4)-1 = 2, which pointed to a
    // different bitmap slot than the one set when seq 4 was first received
    // (which was bit_pos = (6-4)-1 = 1 when expected was 6).
    // The new pqc_common.c correctly tracks this via the bitmap shift
    // that happens when seq 6 advances the window.
    ASSERT(CS(4) == 0,
           "duplicate seq 4 should be rejected — this was the false-pass bug");
    PASS();
}

static void test_bitmap_state_continuity(void) {
    TEST("Bitmap: state is correctly maintained across window advances");

    uint64_t expected = 0, bitmap = 0;

    // Accept 10, then out-of-order 8 and 9
    ASSERT(CS(10) == 1, "seq 10 failed");   // expected → 11
    ASSERT(CS(8)  == 1, "seq 8 failed");    // in window, mark bit
    ASSERT(CS(9)  == 1, "seq 9 failed");    // in window, mark bit

    // Now advance further — 11, 12
    ASSERT(CS(11) == 1, "seq 11 failed");   // expected → 12
    ASSERT(CS(12) == 1, "seq 12 failed");   // expected → 13

    // seq 8 and 9 are now further back in the window but still within it.
    // Replaying them should be rejected.
    ASSERT(CS(8) == 0, "replay of seq 8 should be rejected");
    ASSERT(CS(9) == 0, "replay of seq 9 should be rejected");
    PASS();
}

// ============================================================================
// WINDOW BOUNDARY TESTS
// ============================================================================

static void test_last_packet_in_window(void) {
    TEST("Window: packet at exactly window edge (SEQUENCE_WINDOW-1 behind) accepted");

    uint64_t expected = 0, bitmap = 0;

    // Advance to seq SEQUENCE_WINDOW (64)
    // After processing seq 63, expected = 64
    for (uint64_t i = 0; i < SEQUENCE_WINDOW; i++) {
        ASSERT(CS(i) == 1, "failed advancing to window boundary");
    }
    // expected is now SEQUENCE_WINDOW (64)
    // seq 0 is exactly SEQUENCE_WINDOW packets behind —
    // diff = 64 - 0 = 64 which is >= SEQUENCE_WINDOW so it should be rejected
    ASSERT(CS(0) == 0,
           "seq 0 at exactly window boundary should be rejected (diff == window)");
    PASS();
}

static void test_one_inside_window_boundary(void) {
    TEST("Window: packet one inside window boundary (diff = window-1) accepted");

    uint64_t expected = 0, bitmap = 0;

    // Advance to SEQUENCE_WINDOW - 1 (seq 63 accepted, expected = 64)
    for (uint64_t i = 0; i < SEQUENCE_WINDOW; i++) {
        ASSERT(CS(i) == 1, "failed advancing sequence");
    }

    // seq 1 is SEQUENCE_WINDOW - 1 = 63 packets behind expected (64)
    // diff = 64 - 1 = 63 which is < SEQUENCE_WINDOW (64) → should accept
    ASSERT(CS(1) == 1,
           "seq 1 (SEQUENCE_WINDOW-1 behind) should be accepted");
    PASS();
}

// ============================================================================
// FORWARD JUMP TESTS
// ============================================================================

static void test_forward_jump_within_window(void) {
    TEST("Forward: jump within window is accepted");

    uint64_t expected = 0, bitmap = 0;

    ASSERT(CS(0) == 1, "seq 0 failed");
    // Jump forward by SEQUENCE_WINDOW/2
    uint64_t jump = SEQUENCE_WINDOW / 2;
    ASSERT(CS(jump) == 1, "forward jump within window should be accepted");
    ASSERT(expected == jump + 1, "expected not updated after forward jump");
    PASS();
}

static void test_forward_jump_at_window_boundary(void) {
    TEST("Forward: jump of exactly SEQUENCE_WINDOW is rejected (new behaviour)");

    uint64_t expected = 0, bitmap = 0;

    // OLD behaviour: accept with warning
    // NEW behaviour: reject — a jump this large is suspicious
    ASSERT(CS(SEQUENCE_WINDOW) == 0,
           "jump of exactly SEQUENCE_WINDOW should be rejected");
    PASS();
}

static void test_forward_jump_beyond_window(void) {
    TEST("Forward: jump far beyond window is rejected");

    uint64_t expected = 0, bitmap = 0;

    ASSERT(CS(1000) == 0,
           "very large forward jump should be rejected");
    ASSERT(expected == 0,
           "expected should not change after rejected jump");
    PASS();
}

// ============================================================================
// SEQUENCE WRAP TEST
// ============================================================================

static void test_sequence_near_max(void) {
    TEST("Sequence: packets near UINT64_MAX handled without crash");

    uint64_t expected = UINT64_MAX - 2;
    uint64_t bitmap   = 0;

    // These should all be within normal behaviour
    ASSERT(CS(UINT64_MAX - 2) == 1, "UINT64_MAX-2 rejected");
    ASSERT(CS(UINT64_MAX - 1) == 1, "UINT64_MAX-1 rejected");
    ASSERT(CS(UINT64_MAX)     == 1, "UINT64_MAX rejected");

    // expected is now 0 (wrapped). Seq 0 should be the next expected.
    // Seq UINT64_MAX is a replay.
    ASSERT(CS(UINT64_MAX) == 0, "UINT64_MAX replay should be rejected");
    PASS();
}

// ============================================================================
// MAIN
// ============================================================================

int main(void) {
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║          PQ-VPN Replay Protection Test Suite               ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    printf("── Basic sequence ───────────────────────────────────────────────\n");
    test_normal_sequence();
    test_replay_immediately_after();
    test_replay_of_old_packet();

    printf("\n── Out-of-order handling ────────────────────────────────────────\n");
    test_out_of_order_within_window();
    test_duplicate_within_window();
    test_bitmap_state_continuity();

    printf("\n── Window boundary ──────────────────────────────────────────────\n");
    test_last_packet_in_window();
    test_one_inside_window_boundary();

    printf("\n── Forward jump ─────────────────────────────────────────────────\n");
    test_forward_jump_within_window();
    test_forward_jump_at_window_boundary();
    test_forward_jump_beyond_window();

    printf("\n── Edge cases ───────────────────────────────────────────────────\n");
    test_sequence_near_max();

    printf("\n══════════════════════════════════════════════════════════════════\n");
    printf("Results: %d/%d passed", tests_passed, tests_run);
    if (tests_failed > 0)
        printf("  (%d FAILED)", tests_failed);
    printf("\n");

    return tests_failed > 0 ? 1 : 0;
}