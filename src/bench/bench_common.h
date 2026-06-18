// bench_common.h
// Shared types and helper functions for the benchmark suite.
//
// All three benchmarks (KEM, signature, AEAD) use the same statistics
// structure and computation so results are directly comparable and
// can be written to a single CSV file.

#ifndef BENCH_COMMON_H
#define BENCH_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

#define BENCH_LABEL_LEN     64
#define BENCH_MAX_RESULTS   32

// ============================================================================
// RESULT STRUCTURE
// ============================================================================

typedef struct {
    char    label[BENCH_LABEL_LEN];
    int     iterations;
    double  min_us;
    double  max_us;
    double  mean_us;
    double  median_us;
    double  stddev_us;
    long    data_size;     // bytes — key size, ciphertext size, etc.
} bench_results_t;

// Collects all results from a benchmark run for CSV export
typedef struct {
    bench_results_t results[BENCH_MAX_RESULTS];
    int             count;
} bench_suite_t;

// ============================================================================
// TIMING HELPER
// ============================================================================

// Returns elapsed microseconds between two timespec samples.
static inline double elapsed_us(struct timespec t1, struct timespec t2) {
    return (t2.tv_sec  - t1.tv_sec)  * 1e6 +
           (t2.tv_nsec - t1.tv_nsec) / 1e3;
}

// ============================================================================
// STATISTICS
// ============================================================================

// Compute min/max/mean/median/stddev from an array of timing samples.
// Modifies the input array (sorts it in place) to compute the median.
void bench_compute_stats(double *samples, int n, bench_results_t *out);

// ============================================================================
// SUITE MANAGEMENT
// ============================================================================

// Add a result to the suite for later CSV export.
void bench_suite_add(bench_suite_t *suite, const bench_results_t *r);

// Write all results in the suite to a CSV file.
// Format: label,iterations,min_us,max_us,mean_us,median_us,stddev_us,data_size
int bench_suite_write_csv(const bench_suite_t *suite, const char *path);

// ============================================================================
// DISPLAY
// ============================================================================

// Print a single result as a formatted table row.
void bench_print_result(const bench_results_t *r);

// Print a section header.
void bench_print_header(const char *title);

#endif // BENCH_COMMON_H
