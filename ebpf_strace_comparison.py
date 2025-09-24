#!/usr/bin/env python3

"""
Compare eBPF and strace results to understand I/O amplification
eBPF shows actual device I/O, strace shows syscall path
"""

import re
import sys
from pathlib import Path

# Based on your actual experiment results from document
EBPF_RESULTS = {
    # From your separate_rw_results_20250924_143255
    'write': {
        '1B':    {'app': 40477763, 'os': 700981248, 'device': 8192, 'amplification': 8192.0},
        '10B':   {'app': 40500295, 'os': 726851584, 'device': 12288, 'amplification': 1228.8},
        '100B':  {'app': 40447847, 'os': 643002368, 'device': 8192, 'amplification': 81.9},
        '1KB':   {'app': 41908260, 'os': 578981888, 'device': 57344, 'amplification': 56.0},
        '10KB':  {'app': 41966209, 'os': 618565632, 'device': 24576, 'amplification': 2.4},
        '100KB': {'app': 42248632, 'os': 618741760, 'device': 217088, 'amplification': 2.1},
        '1MB':   {'app': 43876874, 'os': 635760640, 'device': 1060864, 'amplification': 1.0},
        '10MB':  {'app': 52783342, 'os': 693563392, 'device': 9465856, 'amplification': 0.9},
        '100MB': {'app': 126606299, 'os': 680534016, 'device': 86089728, 'amplification': 0.8}
    },
    'read': {
        '1B':    {'app': 12747, 'os': 8192, 'device': 12288, 'amplification': 12288.0},
        '10B':   {'app': 17788, 'os': 8192, 'device': 12288, 'amplification': 1228.8},
        '100B':  {'app': 5770, 'os': 8192, 'device': 12288, 'amplification': 122.9},
        '1KB':   {'app': 17873, 'os': 8192, 'device': 12288, 'amplification': 12.0},
        '10KB':  {'app': 12288, 'os': 4096, 'device': 8192, 'amplification': 0.8},
        '100KB': {'app': 119257, 'os': 4096, 'device': 86016, 'amplification': 0.8},
        '1MB':   {'app': 25352, 'os': 16384, 'device': 544768, 'amplification': 0.5},
        '10MB':  {'app': 4212269, 'os': 8192, 'device': 6094848, 'amplification': 0.6},
        '100MB': {'app': 32674110, 'os': 10592256, 'device': 62578688, 'amplification': 0.6}
    }
}

# From your strace results
STRACE_RESULTS = {
    'write': {
        '1B':    {'xl_meta': 4, 'part_files': 0, 'syscalls': 422},
        '10B':   {'xl_meta': 29, 'part_files': 0, 'syscalls': 1021},
        '100B':  {'xl_meta': 4, 'part_files': 0, 'syscalls': 891},
        '1KB':   {'xl_meta': 4, 'part_files': 0, 'syscalls': 394},
        '10KB':  {'xl_meta': 4, 'part_files': 0, 'syscalls': 400},
        '100KB': {'xl_meta': 4, 'part_files': 0, 'syscalls': 352},
        '1MB':   {'xl_meta': 4, 'part_files': 1, 'syscalls': 550},
        '10MB':  {'xl_meta': 11, 'part_files': 14, 'syscalls': 1241},
    },
    'read': {
        '1B':    {'xl_meta': 2, 'part_files': 0, 'syscalls': 398},
        '10B':   {'xl_meta': 2, 'part_files': 0, 'syscalls': 398},
        '100B':  {'xl_meta': 2, 'part_files': 0, 'syscalls': 417},
        '1KB':   {'xl_meta': 2, 'part_files': 0, 'syscalls': 378},
        '10KB':  {'xl_meta': 37, 'part_files': 0, 'syscalls': 1671},
        '100KB': {'xl_meta': 2, 'part_files': 0, 'syscalls': 413},
        '1MB':   {'xl_meta': 2, 'part_files': 1, 'syscalls': 487},
        '10MB':  {'xl_meta': 3, 'part_files': 2, 'syscalls': 1216},
    }
}

def analyze_combined_results():
    """Compare eBPF and strace results"""

    sizes = {
        '1B': 1, '10B': 10, '100B': 100, '1KB': 1024, '10KB': 10240,
        '100KB': 102400, '1MB': 1048576, '10MB': 10485760, '100MB': 104857600
    }

    print("=" * 100)
    print("COMBINED EBPF AND STRACE ANALYSIS")
    print("=" * 100)
    print()
    print("Key Definitions:")
    print("  • I/O Amplification = Device Layer Bytes (eBPF) / Object Size")
    print("  • This is the ACTUAL amplification at the block device level")
    print("  • strace shows the syscall path and metadata operations")
    print()

    # Summary table
    print("─" * 100)
    print(f"{'Size':>6} │ {'Object':>10} │ {'Device I/O':>12} │ {'I/O Amp':>10} │ {'xl.meta':>8} │ {'Syscalls':>8} │ {'Insight':>30}")
    print("─" * 100)

    for size_name, size_bytes in sizes.items():
        if size_name not in EBPF_RESULTS['write']:
            continue

        w_ebpf = EBPF_RESULTS['write'][size_name]
        w_strace = STRACE_RESULTS['write'].get(size_name, {})

        # Calculate true I/O amplification
        true_amp = w_ebpf['device'] / size_bytes

        # Determine insight
        if w_strace.get('xl_meta', 0) > 4:
            insight = f"High metadata overhead ({w_strace['xl_meta']} ops)"
        elif w_strace.get('part_files', 0) > 0:
            insight = f"Uses erasure coding ({w_strace['part_files']} parts)"
        elif true_amp > 100:
            insight = "Extreme amplification from metadata"
        elif true_amp > 10:
            insight = "High amplification"
        else:
            insight = "Normal operation"

        print(f"{size_name:>6} │ {size_bytes:>10,} │ {w_ebpf['device']:>12,} │ {true_amp:>10.1f}x │ "
              f"{w_strace.get('xl_meta', 0):>8} │ {w_strace.get('syscalls', 0):>8} │ {insight:>30}")

    print("─" * 100)

    # Detailed analysis per size
    print("\n" + "=" * 100)
    print("DETAILED ANALYSIS BY SIZE")
    print("=" * 100)

    for size_name, size_bytes in sizes.items():
        if size_name not in EBPF_RESULTS['write']:
            continue

        print(f"\n{size_name} ({size_bytes:,} bytes)")
        print("─" * 60)

        # Write analysis
        w_ebpf = EBPF_RESULTS['write'][size_name]
        w_strace = STRACE_RESULTS['write'].get(size_name, {})

        print("WRITE Operation:")
        print(f"  eBPF Measurements:")
        print(f"    Application: {w_ebpf['app']:,} bytes")
        print(f"    OS Layer:    {w_ebpf['os']:,} bytes")
        print(f"    Device I/O:  {w_ebpf['device']:,} bytes")
        print(f"    → True I/O Amplification: {w_ebpf['device']/size_bytes:.1f}x")

        print(f"  strace Analysis:")
        print(f"    xl.meta operations: {w_strace.get('xl_meta', 0)}")
        print(f"    Part files:        {w_strace.get('part_files', 0)}")
        print(f"    Total syscalls:    {w_strace.get('syscalls', 0)}")

        # Metadata overhead estimation
        if w_strace.get('xl_meta', 0) > 0:
            estimated_metadata = w_strace['xl_meta'] * 4096  # Assume 4KB per xl.meta
            print(f"    Estimated metadata overhead: {estimated_metadata:,} bytes")

        # Read analysis
        if size_name in EBPF_RESULTS['read']:
            r_ebpf = EBPF_RESULTS['read'][size_name]
            r_strace = STRACE_RESULTS['read'].get(size_name, {})

            print("\nREAD Operation:")
            print(f"  eBPF Measurements:")
            print(f"    Application: {r_ebpf['app']:,} bytes")
            print(f"    OS Layer:    {r_ebpf['os']:,} bytes")
            print(f"    Device I/O:  {r_ebpf['device']:,} bytes")
            print(f"    → True I/O Amplification: {r_ebpf['device']/size_bytes:.1f}x")

            print(f"  strace Analysis:")
            print(f"    xl.meta operations: {r_strace.get('xl_meta', 0)}")
            print(f"    Part files:        {r_strace.get('part_files', 0)}")
            print(f"    Total syscalls:    {r_strace.get('syscalls', 0)}")

    # Key findings
    print("\n" + "=" * 100)
    print("KEY FINDINGS")
    print("=" * 100)

    print("\n1. EXTREME AMPLIFICATION FOR SMALL OBJECTS:")
    print("   • 1B write: 8,192x amplification (8KB written to device)")
    print("   • This is due to minimum block size and metadata overhead")
    print("   • strace shows 4 xl.meta operations, each likely 4KB")

    print("\n2. METADATA OVERHEAD PATTERNS:")
    print("   • Small objects (≤1KB): Consistent 4 xl.meta operations")
    print("   • 10B anomaly: 29 xl.meta operations (needs investigation)")
    print("   • 10KB read anomaly: 37 xl.meta operations (cache miss?)")

    print("\n3. ERASURE CODING THRESHOLD:")
    print("   • Starts at 1MB: Part files appear")
    print("   • 10MB: 14 part files with 11 xl.meta operations")
    print("   • This explains the lower amplification for large objects")

    print("\n4. AMPLIFICATION TRENDS:")
    print("   • Small objects (≤1KB): 12x-8192x amplification")
    print("   • Medium objects (10KB-100KB): 2-3x amplification")
    print("   • Large objects (≥1MB): <1x amplification (compression?)")

    print("\n5. SYSCALL vs DEVICE I/O:")
    print("   • eBPF app bytes include HTTP/protocol overhead")
    print("   • Device I/O is the actual disk writes (submit_bio)")
    print("   • strace helps identify the syscall path between them")

if __name__ == "__main__":
    analyze_combined_results()
