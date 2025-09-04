#!/usr/bin/env python3
"""
Simple Trace Analyzer and Validator
Validates and analyzes trace output from the eBPF multilayer I/O tracer
"""

import re
import sys
from collections import defaultdict, Counter
from datetime import datetime

def parse_trace_file(filename):
    """Parse trace file and extract events and summary"""
    
    events = []
    summary_section = []
    is_summary = False
    
    print(f"Reading trace file: {filename}")
    
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        return [], []
    
    for line in lines:
        # Check for summary section
        if "I/O AMPLIFICATION ANALYSIS" in line or "TOTAL AMPLIFICATION" in line:
            is_summary = True
        
        if is_summary:
            summary_section.append(line.strip())
        else:
            # Parse event lines (non-header, non-empty lines)
            if line.strip() and not line.startswith('TIME') and not '====' in line:
                events.append(line.strip())
    
    return events, summary_section

def validate_trace_format(events):
    """Validate that events have the expected format"""
    
    print("\n=== TRACE FORMAT VALIDATION ===")
    
    if not events:
        print("❌ No events found in trace!")
        return False
    
    print(f"✓ Found {len(events)} events")
    
    # Check a sample of events for proper format
    valid_count = 0
    invalid_lines = []
    
    # Expected format: TIME.ms LAYER EVENT SIZE ALIGNED LAT(μs) COMM [FLAGS]
    event_pattern = r'^\d{2}:\d{2}:\d{2}\.\d+ \S+ \S+ \d+ \d+ [\d.]+ \S+'
    
    for i, event in enumerate(events[:10]):  # Check first 10 events
        if re.search(r'\d{2}:\d{2}:\d{2}\.\d+', event):  # Has timestamp
            valid_count += 1
        else:
            invalid_lines.append((i+1, event[:50]))
    
    if valid_count > 0:
        print(f"✓ {valid_count}/{min(10, len(events))} events have valid timestamp format")
    else:
        print(f"❌ No valid event formats found")
        print("Invalid lines:")
        for line_no, content in invalid_lines[:5]:
            print(f"  Line {line_no}: {content}...")
    
    return valid_count > 0

def analyze_layers(events):
    """Analyze events by layer"""
    
    print("\n=== LAYER ANALYSIS ===")
    
    layers = Counter()
    layer_bytes = defaultdict(int)
    layer_events = defaultdict(list)
    
    for event in events:
        parts = event.split()
        if len(parts) >= 7:
            layer = parts[1]
            try:
                size = int(parts[3])
                aligned = int(parts[4])
                
                layers[layer] += 1
                layer_bytes[layer] += size
                layer_events[layer].append({
                    'size': size,
                    'aligned': aligned,
                    'event_type': parts[2]
                })
            except (ValueError, IndexError):
                continue
    
    if not layers:
        print("❌ No layer information found")
        return None
    
    print(f"✓ Found {len(layers)} different layers:")
    for layer, count in sorted(layers.items()):
        avg_size = layer_bytes[layer] / count if count > 0 else 0
        print(f"  • {layer:15} : {count:6} events, {layer_bytes[layer]:10} bytes total, {avg_size:8.1f} avg bytes")
    
    return layer_events

def check_amplification(events, summary):
    """Check for I/O amplification patterns"""
    
    print("\n=== AMPLIFICATION CHECK ===")
    
    # Look for amplification in summary
    if summary:
        for line in summary:
            if "TOTAL AMPLIFICATION" in line:
                print(f"✓ {line}")
                # Extract amplification factor
                match = re.search(r'(\d+\.?\d*)x', line)
                if match:
                    factor = float(match.group(1))
                    if factor > 1.0:
                        print(f"  ⚠️  Detected {factor}x amplification!")
                    else:
                        print(f"  ✓ No significant amplification (factor: {factor})")
                return
    
    # Manual calculation from events if no summary
    layer_totals = defaultdict(int)
    for event in events:
        parts = event.split()
        if len(parts) >= 5:
            layer = parts[1]
            try:
                size = int(parts[3])
                layer_totals[layer] += size
            except (ValueError, IndexError):
                continue
    
    if 'APPLICATION' in layer_totals and 'DEVICE' in layer_totals:
        if layer_totals['APPLICATION'] > 0:
            amplification = layer_totals['DEVICE'] / layer_totals['APPLICATION']
            print(f"  Calculated amplification: {amplification:.2f}x")
            print(f"  App bytes: {layer_totals['APPLICATION']}, Device bytes: {layer_totals['DEVICE']}")
    else:
        print("  ⚠️  Could not calculate amplification (missing layer data)")

def analyze_event_types(events):
    """Analyze different event types"""
    
    print("\n=== EVENT TYPE ANALYSIS ===")
    
    event_types = Counter()
    
    for event in events:
        parts = event.split()
        if len(parts) >= 3:
            event_type = parts[2]
            event_types[event_type] += 1
    
    if event_types:
        print(f"✓ Found {len(event_types)} different event types:")
        for event_type, count in event_types.most_common(10):
            print(f"  • {event_type:25} : {count:6} occurrences")
    else:
        print("❌ No event types found")

def check_timing_consistency(events):
    """Check if timestamps are consistent"""
    
    print("\n=== TIMING CONSISTENCY CHECK ===")
    
    timestamps = []
    
    for event in events[:100]:  # Check first 100 events
        match = re.search(r'(\d{2}:\d{2}:\d{2}\.\d+)', event)
        if match:
            timestamps.append(match.group(1))
    
    if len(timestamps) > 1:
        print(f"✓ Found {len(timestamps)} timestamps")
        print(f"  First event: {timestamps[0]}")
        print(f"  Last event:  {timestamps[-1]}")
        
        # Check if timestamps are increasing
        try:
            # Simple check - comparing string timestamps
            if timestamps[0] <= timestamps[-1]:
                print("  ✓ Timestamps appear to be in order")
            else:
                print("  ⚠️  Timestamps may be out of order")
        except:
            pass
    else:
        print("❌ Not enough timestamps found")

def generate_summary(events):
    """Generate a summary of the trace"""
    
    print("\n=== TRACE SUMMARY ===")
    
    # Count flags
    metadata_count = sum(1 for e in events if '[META]' in e)
    journal_count = sum(1 for e in events if '[JRNL]' in e)
    cache_hit_count = sum(1 for e in events if '[HIT]' in e)
    
    print(f"Total events:     {len(events)}")
    print(f"Metadata ops:     {metadata_count}")
    print(f"Journal ops:      {journal_count}")
    print(f"Cache hits:       {cache_hit_count}")
    
    # Find unique processes
    processes = set()
    for event in events:
        parts = event.split()
        if len(parts) >= 7:
            processes.add(parts[6])
    
    if processes:
        print(f"Unique processes: {len(processes)}")
        print(f"  Processes: {', '.join(list(processes)[:10])}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 analyze_trace.py <trace_file>")
        print("\nExample:")
        print("  python3 analyze_trace.py trace.txt")
        sys.exit(1)
    
    filename = sys.argv[1]
    
    print("="*50)
    print("    eBPF I/O TRACE ANALYZER")
    print("="*50)
    
    # Parse the trace file
    events, summary = parse_trace_file(filename)
    
    if not events and not summary:
        print("\n❌ No data found in trace file!")
        print("\nPossible issues:")
        print("  1. Tracer didn't capture any events")
        print("  2. Trace file is empty")
        print("  3. Wrong file format")
        sys.exit(1)
    
    # Run validation checks
    is_valid = validate_trace_format(events)
    
    if is_valid:
        # Perform analysis
        layer_data = analyze_layers(events)
        analyze_event_types(events)
        check_timing_consistency(events)
        check_amplification(events, summary)
        generate_summary(events)
        
        print("\n" + "="*50)
        print("✓ ANALYSIS COMPLETE")
        print("="*50)
        
        # Provide recommendations
        print("\n=== RECOMMENDATIONS ===")
        
        if not summary:
            print("⚠️  No amplification summary found in trace.")
            print("   Try running with: sudo ./working_trace.sh 10 trace.txt")
            print("   Make sure to let it complete or interrupt with Ctrl+C")
        
        if len(events) < 10:
            print("⚠️  Very few events captured.")
            print("   Try running I/O operations during tracing:")
            print("   - dd if=/dev/zero of=test.dat bs=4K count=1000")
            print("   - echo 'test' > file.txt && sync")
        
        if layer_data and 'APPLICATION' not in [l for l in layer_data.keys()]:
            print("⚠️  No APPLICATION layer events found.")
            print("   The tracer may not be capturing app-level I/O.")
        
    else:
        print("\n❌ Trace format validation failed!")
        print("\nTroubleshooting steps:")
        print("  1. Check if tracer is built: make multi")
        print("  2. Run with sudo: sudo ./working_trace.sh 5 test.txt")
        print("  3. Check kernel support: ls /sys/kernel/debug/tracing/")

if __name__ == "__main__":
    main()
