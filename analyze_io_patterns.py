#!/usr/bin/env python3
import sys
import re
from collections import defaultdict

class IOAnalyzer:
    def __init__(self):
        self.data_io = defaultdict(int)
        self.metadata_io = defaultdict(int)
        self.journal_io = defaultdict(int)
        self.by_layer = defaultdict(lambda: {'data': 0, 'metadata': 0, 'journal': 0})
        self.amplification = {}
        
    def analyze_file(self, filename):
        with open(filename, 'r') as f:
            current_test = None
            app_size = 0
            device_size = 0
            
            for line in f:
                # Track test markers
                if 'MARKER:' in line:
                    if current_test and app_size > 0:
                        self.amplification[current_test] = device_size / app_size if app_size else 0
                    current_test = line.split('MARKER:')[1].strip()
                    app_size = 0
                    device_size = 0
                
                # Categorize I/O types
                if '[META]' in line or 'XL.META' in line or 'metadata' in line.lower():
                    self.metadata_io['count'] += 1
                    size = self.extract_size(line)
                    self.metadata_io['bytes'] += size
                    
                elif '[JRNL]' in line or 'journal' in line.lower() or 'FS_SYNC' in line:
                    self.journal_io['count'] += 1
                    size = self.extract_size(line)
                    self.journal_io['bytes'] += size
                    
                else:
                    # Regular data I/O
                    if any(x in line for x in ['READ', 'WRITE', 'BIO']):
                        self.data_io['count'] += 1
                        size = self.extract_size(line)
                        self.data_io['bytes'] += size
                
                # Track by layer
                for layer in ['APPLICATION', 'STORAGE_SVC', 'OS', 'FILESYSTEM', 'DEVICE']:
                    if layer in line:
                        size = self.extract_size(line)
                        if '[META]' in line or 'metadata' in line.lower():
                            self.by_layer[layer]['metadata'] += size
                        elif '[JRNL]' in line or 'journal' in line.lower():
                            self.by_layer[layer]['journal'] += size
                        else:
                            self.by_layer[layer]['data'] += size
                        
                        # Track amplification
                        if layer == 'APPLICATION':
                            app_size = max(app_size, size)
                        elif layer == 'DEVICE':
                            device_size = max(device_size, size)
    
    def extract_size(self, line):
        # Extract size from trace line
        parts = line.split()
        for i, part in enumerate(parts):
            if part.isdigit() and int(part) > 0:
                return int(part)
        return 0
    
    def print_report(self):
        print("=" * 70)
        print("I/O PATTERN ANALYSIS REPORT")
        print("=" * 70)
        
        print("\n1. I/O TYPE BREAKDOWN:")
        print("-" * 40)
        total_bytes = self.data_io['bytes'] + self.metadata_io['bytes'] + self.journal_io['bytes']
        
        if total_bytes > 0:
            print(f"Data I/O:     {self.data_io['bytes']:12,} bytes ({self.data_io['bytes']*100/total_bytes:.1f}%)")
            print(f"Metadata I/O: {self.metadata_io['bytes']:12,} bytes ({self.metadata_io['bytes']*100/total_bytes:.1f}%)")
            print(f"Journal I/O:  {self.journal_io['bytes']:12,} bytes ({self.journal_io['bytes']*100/total_bytes:.1f}%)")
        
        print(f"\nOperation counts:")
        print(f"Data ops:     {self.data_io['count']:8,}")
        print(f"Metadata ops: {self.metadata_io['count']:8,}")
        print(f"Journal ops:  {self.journal_io['count']:8,}")
        
        print("\n2. I/O BY LAYER:")
        print("-" * 40)
        for layer in ['APPLICATION', 'STORAGE_SVC', 'OS', 'FILESYSTEM', 'DEVICE']:
            if layer in self.by_layer:
                l = self.by_layer[layer]
                total = l['data'] + l['metadata'] + l['journal']
                if total > 0:
                    print(f"\n{layer}:")
                    print(f"  Data:     {l['data']:10,} bytes")
                    print(f"  Metadata: {l['metadata']:10,} bytes")
                    print(f"  Journal:  {l['journal']:10,} bytes")
        
        print("\n3. AMPLIFICATION BY TEST:")
        print("-" * 40)
        for test, amp in sorted(self.amplification.items()):
            if amp > 0:
                print(f"{test[:50]:50s}: {amp:6.1f}x")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 analyze_io_patterns.py <trace_file>")
        sys.exit(1)
    
    analyzer = IOAnalyzer()
    analyzer.analyze_file(sys.argv[1])
    analyzer.print_report()
