// test_replay.c - Test replay protection
#include <stdio.h>
#include <stdint.h>
#include "../common/pqc_common.h"

int main() {
    printf("Testing Replay Protection\n\n");
    
    uint64_t expected_seq = 0;
    uint64_t seq_bitmap = 0;
    
    // Test 1: Normal sequence
    printf("Test 1: Normal sequence (0, 1, 2, 3)\n");
    for (uint64_t i = 0; i < 4; i++) {
        int result = check_sequence(i, &expected_seq, &seq_bitmap);
        printf("  Seq %lu: %s\n", i, result ? "✅ Accepted" : "❌ Rejected");
    }
    printf("  Expected: 4, Bitmap: 0x%lx\n\n", seq_bitmap);
    
    // Test 2: Replay attack
    printf("Test 2: Replay attack (seq 2 again)\n");
    int result = check_sequence(2, &expected_seq, &seq_bitmap);
    printf("  Seq 2: %s (should be REJECTED)\n\n", result ? "❌ Accepted" : "✅ Rejected");
    
    // Test 3: Out of order (within window)
    printf("Test 3: Out of order (5, 4, 6)\n");
    expected_seq = 5;
    seq_bitmap = 0;
    
    result = check_sequence(5, &expected_seq, &seq_bitmap);
    printf("  Seq 5: %s\n", result ? "✅ Accepted" : "❌ Rejected");
    
    result = check_sequence(4, &expected_seq, &seq_bitmap);
    printf("  Seq 4: %s (out of order, but in window)\n", result ? "✅ Accepted" : "❌ Rejected");
    
    result = check_sequence(6, &expected_seq, &seq_bitmap);
    printf("  Seq 6: %s\n\n", result ? "✅ Accepted" : "❌ Rejected");
    
    // Test 4: Duplicate
    printf("Test 4: Duplicate (seq 4 again)\n");
    result = check_sequence(4, &expected_seq, &seq_bitmap);
    printf("  Seq 4: %s (should be REJECTED - duplicate)\n\n", 
           result ? "❌ Accepted" : "✅ Rejected");
    
    printf("✅ All replay protection tests completed\n");
    return 0;
}