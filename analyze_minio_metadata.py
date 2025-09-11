#!/usr/bin/env python3
import json
import sys
from collections import defaultdict

def analyze_metadata_io(logfile):
    stats = {
        'xl_meta_ops': 0,
        'xl_meta_bytes': 0,
        'metadata_reads': 0,
        'metadata_writes': 0,
        'data_vs_metadata_ratio': 0,
        'operations': defaultdict(int),
        'layer_metadata': defaultdict(lambda: {'count': 0, 'bytes': 0})
    }
    
    with open(logfile, 'r') as f:
        for line in f:
            if 'XL.META' in line or 'xl.meta' in line:
                stats['xl_meta_ops'] += 1
                # Extract size if available
                parts = line.split()
                for i, part in enumerate(parts):
                    if part.isdigit() and i > 0:
                        stats['xl_meta_bytes'] += int(part)
                        break
            
            if 'EVENT_MINIO_XL_META' in line or 'MINIO_XL_META' in line:
                stats['metadata_writes'] += 1
            
            if 'is_metadata' in line or '[META]' in line:
                stats['metadata_reads'] += 1
                
            # Track by layer
            for layer in ['APPLICATION', 'STORAGE_SVC', 'OS', 'FILESYSTEM', 'DEVICE']:
                if layer in line and ('[META]' in line or 'metadata' in line.lower()):
                    stats['layer_metadata'][layer]['count'] += 1
    
    # Print analysis
    print("=" * 60)
    print("MinIO METADATA I/O ANALYSIS")
    print("=" * 60)
    print(f"XL.META Operations:      {stats['xl_meta_ops']}")
    print(f"XL.META Total Bytes:     {stats['xl_meta_bytes']:,}")
    print(f"Metadata Reads:          {stats['metadata_reads']}")
    print(f"Metadata Writes:         {stats['metadata_writes']}")
    print()
    print("Metadata by Layer:")
    for layer, data in stats['layer_metadata'].items():
        print(f"  {layer:15s}: {data['count']} operations")
    print()
    
    # Calculate metadata overhead
    if stats['xl_meta_ops'] > 0:
        avg_metadata_size = stats['xl_meta_bytes'] / stats['xl_meta_ops']
        print(f"Average metadata size:   {avg_metadata_size:.0f} bytes")
        print(f"Metadata ops ratio:      {stats['metadata_reads']}/{stats['metadata_writes']} (R/W)")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 analyze_minio_metadata.py <logfile>")
        sys.exit(1)
    analyze_metadata_io(sys.argv[1])
