// bench_main.c
// PQ-VPN Cryptographic Benchmark Suite
//
// Runs all three benchmarks (KEM, signature, AEAD) and writes
// combined results to a CSV file for use in dissertation charts.
//
// Usage:
//   ./bin/bench_crypto                  → runs all, writes bench_results.csv
//   ./bin/bench_crypto --output FILE    → custom output path
//   ./bin/bench_crypto --tag LABEL      → adds a tag column (e.g. "local"
//                                          or "cloud") to identify which
//                                          machine the results came from
//
// This tool is standalone — it does not touch or depend on vpn_server,
// vpn_client, or session.c. It links only against pqc_common (for the
// elapsed_us inline, though bench_common.h has its own copy) and the
// cryptographic libraries directly.

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bench_common.h"

// Forward declarations — implemented in bench_kem.c, bench_sig.c, bench_aead.c
void run_kem_benchmark(bench_suite_t *suite);
void run_sig_benchmark(bench_suite_t *suite);
void run_aead_benchmark(bench_suite_t *suite);

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char *argv[]) {
    const char *output_path = "bench_results.csv";
    const char *tag = "untagged";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--output") == 0 && i + 1 < argc)
            output_path = argv[++i];
        else if (strcmp(argv[i], "--tag") == 0 && i + 1 < argc)
            tag = argv[++i];
        else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [--output FILE] [--tag LABEL]\n", argv[0]);
            printf("  --output FILE   CSV output path (default: bench_results.csv)\n");
            printf("  --tag LABEL     Tag for this run, e.g. 'local' or 'cloud'\n");
            return 0;
        }
    }

    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║          PQ-VPN Cryptographic Benchmark Suite             ║\n");
    printf("║          Post-Quantum vs Classical Algorithm Comparison    ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");
    printf("\n  Tag        : %s\n", tag);
    printf("  Output     : %s\n", output_path);

    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S UTC",
             gmtime(&now));
    printf("  Started    : %s\n", timestamp);

    bench_suite_t suite;
    memset(&suite, 0, sizeof(suite));

    struct timespec suite_start, suite_end;
    clock_gettime(CLOCK_MONOTONIC, &suite_start);

    run_kem_benchmark(&suite);
    run_sig_benchmark(&suite);
    run_aead_benchmark(&suite);

    clock_gettime(CLOCK_MONOTONIC, &suite_end);
    double total_sec = elapsed_us(suite_start, suite_end) / 1e6;

    printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("  Benchmark suite complete in %.2f seconds\n", total_sec);
    printf("  %d total measurements collected\n", suite.count);
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // Write CSV with the tag prepended to each label for easy filtering
    // when comparing local vs cloud runs in a spreadsheet
    FILE *f = fopen(output_path, "w");
    if (!f) {
        fprintf(stderr, "❌ Cannot open '%s' for writing\n", output_path);
        return 1;
    }
    fprintf(f, "tag,label,iterations,min_us,max_us,mean_us,median_us,"
              "stddev_us,data_size_bytes\n");
    for (int i = 0; i < suite.count; i++) {
        const bench_results_t *r = &suite.results[i];
        fprintf(f, "%s,%s,%d,%.3f,%.3f,%.3f,%.3f,%.3f,%ld\n",
                tag, r->label, r->iterations,
                r->min_us, r->max_us, r->mean_us, r->median_us,
                r->stddev_us, r->data_size);
    }
    fclose(f);

    printf("\n📄 Results written to: %s\n", output_path);
    printf("   Import into a spreadsheet for dissertation charts.\n\n");

    return 0;
}
