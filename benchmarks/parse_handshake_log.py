#!/usr/bin/env python3
# parse_handshake_log.py
# Parses handshake_log.txt produced by bench_handshake.sh and computes
# statistics on real end-to-end VPN handshake timing over the actual
# deployed cloud connection.
#
# Usage: python3 parse_handshake_log.py [handshake_log.txt]

import re
import sys
import statistics

LOG_FILE = sys.argv[1] if len(sys.argv) > 1 else "handshake_log.txt"

with open(LOG_FILE, encoding="utf-8", errors="replace") as f:
    content = f.read()

runs = content.split("=== Run ")[1:]
total_runs = len(runs)

successful = []
failed_count = 0

for run in runs:
    if "Handshake complete" in run:
        keypair_m = re.search(r"Keypair:\s*([\d.]+)", run)
        decap_m   = re.search(r"Decapsulation:\s*([\d.]+)", run)

        keypair_us = float(keypair_m.group(1)) if keypair_m else None
        decap_us   = float(decap_m.group(1))   if decap_m   else None

        successful.append({
            "keypair_us": keypair_us,
            "decap_us":   decap_us,
        })
    else:
        failed_count += 1

print("━" * 60)
print("  End-to-End Handshake Benchmark Results")
print("━" * 60)
print(f"  Total runs       : {total_runs}")
print(f"  Successful       : {len(successful)}")
print(f"  Failed           : {failed_count}")
print(f"  Success rate     : {len(successful)/total_runs*100:.0f}%")
print()

if successful:
    keypair_vals = [s["keypair_us"] for s in successful if s["keypair_us"]]
    decap_vals   = [s["decap_us"]   for s in successful if s["decap_us"]]

    def report(name, vals):
        if not vals:
            print(f"  {name}: no data")
            return
        print(f"  {name}:")
        print(f"    n      : {len(vals)}")
        print(f"    mean   : {statistics.mean(vals):.2f} us")
        print(f"    median : {statistics.median(vals):.2f} us")
        print(f"    min    : {min(vals):.2f} us")
        print(f"    max    : {max(vals):.2f} us")
        if len(vals) > 1:
            print(f"    stddev : {statistics.stdev(vals):.2f} us")
        print()

    report("ML-KEM-768 Keypair generation (client side)", keypair_vals)
    report("ML-KEM-768 Decapsulation (client side)",       decap_vals)

    # Write CSV
    with open("handshake_results.csv", "w") as f:
        f.write("run,keypair_us,decap_us\n")
        for i, s in enumerate(successful, 1):
            f.write(f"{i},{s['keypair_us'] or ''},{s['decap_us'] or ''}\n")
    print("  📄 Written to handshake_results.csv")
else:
    print("  No successful runs to analyse.")

print("━" * 60)
