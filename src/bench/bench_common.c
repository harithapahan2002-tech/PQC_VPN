// bench_common.c
// Implementation of shared benchmark statistics, CSV export, and display.

#define _POSIX_C_SOURCE 200809L

#include "bench_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

// ============================================================================
// SORTING HELPER  (for median calculation)
// ============================================================================

static int compare_doubles(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    if (da < db) return -1;
    if (da > db) return  1;
    return 0;
}

// ============================================================================
// STATISTICS
// ============================================================================

void bench_compute_stats(double *samples, int n, bench_results_t *out) {
    if (n <= 0) {
        memset(out, 0, sizeof(*out));
        return;
    }

    // Sort for median — caller's array is modified, which is fine since
    // each benchmark allocates its own array for this single purpose.
    qsort(samples, n, sizeof(double), compare_doubles);

    double sum = 0.0;
    double min = samples[0];
    double max = samples[n - 1];

    for (int i = 0; i < n; i++) sum += samples[i];
    double mean = sum / n;

    double median = (n % 2 == 0) ?
        (samples[n/2 - 1] + samples[n/2]) / 2.0 :
        samples[n/2];

    double sq_diff_sum = 0.0;
    for (int i = 0; i < n; i++) {
        double diff = samples[i] - mean;
        sq_diff_sum += diff * diff;
    }
    double stddev = sqrt(sq_diff_sum / n);

    out->iterations = n;
    out->min_us      = min;
    out->max_us      = max;
    out->mean_us      = mean;
    out->median_us    = median;
    out->stddev_us    = stddev;
    // label and data_size are set by the caller after this returns
}

// ============================================================================
// SUITE MANAGEMENT
// ============================================================================

void bench_suite_add(bench_suite_t *suite, const bench_results_t *r) {
    if (suite->count >= BENCH_MAX_RESULTS) {
        fprintf(stderr, "⚠️  bench_suite: max results reached, dropping '%s'\n",
                r->label);
        return;
    }
    suite->results[suite->count++] = *r;
}

int bench_suite_write_csv(const bench_suite_t *suite, const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "❌ bench: cannot open '%s' for writing\n", path);
        return -1;
    }

    fprintf(f, "label,iterations,min_us,max_us,mean_us,median_us,"
              "stddev_us,data_size_bytes\n");

    for (int i = 0; i < suite->count; i++) {
        const bench_results_t *r = &suite->results[i];
        fprintf(f, "%s,%d,%.3f,%.3f,%.3f,%.3f,%.3f,%ld\n",
                r->label, r->iterations,
                r->min_us, r->max_us, r->mean_us, r->median_us,
                r->stddev_us, r->data_size);
    }

    fclose(f);
    printf("\n📄 Results written to: %s\n", path);
    return 0;
}

// ============================================================================
// DISPLAY
// ============================================================================

void bench_print_header(const char *title) {
    printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("  %s\n", title);
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
}

void bench_print_result(const bench_results_t *r) {
    printf("  %-26s  mean=%9.2f µs  median=%9.2f µs  "
           "min=%8.2f  max=%9.2f  (n=%d, size=%ldB)\n",
           r->label, r->mean_us, r->median_us,
           r->min_us, r->max_us, r->iterations, r->data_size);
}
