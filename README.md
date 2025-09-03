# eBPF I/O Efficiency Tracer

A comprehensive eBPF-based framework for real-time measurement and analysis of I/O amplification in distributed storage systems like MinIO, Ceph, etcd, PostgreSQL, and GlusterFS.

## Overview

This framework provides:
- **Real-time tracing** of I/O operations at syscall, VFS, and block device layers
- **Multi-system support** for various storage systems with automatic detection
- **Low overhead** eBPF probes that can be attached/detached dynamically
- **Comprehensive analysis** tools for calculating amplification factors
- **Rich visualizations** for research and debugging

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Application   │    │   Application   │    │   Application   │
│   (MinIO/Ceph/  │    │   (etcd/Postgres│    │   (GlusterFS)   │
│    etc.)        │    │    etc.)        │    │                 │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          ▼                      ▼                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Syscall Layer (read/write)                   │
│                         eBPF Probe ◄─────────────────────────┐  │
└─────────┬───────────────────────────────────────────────────┼──┘
          │                                                   │
          ▼                                                   │
┌─────────────────────────────────────────────────────────────┼──┐
│                      VFS Layer                              │  │
│                         eBPF Probe ◄─────────────────────────┼─┤
└─────────┬───────────────────────────────────────────────────┼─┘
          │                                                   │
          ▼                                                   │
┌─────────────────────────────────────────────────────────────┼──┐
│                    Block Layer                              │  │
│                         eBPF Probe ◄─────────────────────────┼─┤
└─────────┬───────────────────────────────────────────────────┼─┘
          │                                                   │
          ▼                                                   │
┌─────────────────────────────────────────────────────────────┼──┐
│                  Storage Devices                            │  │
└─────────────────────────────────────────────────────────────┼──┘
                                                              │
                ┌─────────────────────────────────────────────┘
                │
                ▼
    ┌─────────────────────────────────┐
    │       Userspace Program         │
    │   - Ring buffer processing      │
    │   - Real-time analysis          │
    │   - JSON output                 │
    │   - Statistics calculation      │
    └─────────────────────────────────┘
```

## Quick Start

### 1. Install Dependencies

```bash
# Ubuntu/Debian
make setup

# Or manually:
sudo apt-get install -y clang llvm libelf-dev libz-dev libbpf-dev \
    linux-headers-$(uname -r) bpftool python3-pip

# Python dependencies for analysis
pip3 install pandas matplotlib seaborn numpy
```

### 2. Build the Tracer

```bash
make all
```

### multi layer tracer usage 
```bash
# Start tracer for 15 seconds
./working_trace.sh 15 complete_test.txt &
sleep 2

# Generate exactly 10MB of I/O
dd if=/dev/zero of=/tmp/test_10mb.dat bs=1M count=10 conv=fdatasync

# Wait for tracer to finish
wait
```


### 4. Analyze Results

```bash
./analyze_io.sh complete_test.txt
```


### Expected Output
```bash
shwsun@zstore1:~/dev/io-efficiency-eBPF$ ./analyze_io.sh complete_test.txt
=== I/O Amplification Analysis ===
DD write events: 12
Application bytes: 10485853
1MB write count: 10
Device bytes: 10547200

AMPLIFICATION: 1.005x
  Application: 10485853 bytes (10.00 MB)
  Device: 10547200 bytes (10.05 MB)

Sample events:
First dd write:
10:14:57.487 APPLICATION  APP_WRITE                 1048576 1048576     0.00 dd
First device write:
10:14:57.489 DEVICE       DEV_BIO_SUBMIT            8388608 8388608     0.00 dd
```

## Test without caching
```bash
# Test small write (100 bytes -> 512 minimum for O_DIRECT)
sync; echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
./working_trace.sh 5 small_direct.txt &
sleep 1
./direct_io_test 100
wait
echo "=== 100-byte Direct I/O Test ==="
echo "Application writes:"
awk '/direct_io_test.APP_WRITE/ {sum+=$5; n++} END {print "  Count:", n, "Total:", sum}' small_direct.txt
echo "Device writes:"
awk '/DEVICE.BIO_SUBMIT/ {sum+=$5; n++} END {print "  Count:", n, "Total:", sum}' small_direct.txt
# Test 4KB write (page-aligned)
sync; echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
./working_trace.sh 5 page_direct.txt &
sleep 1
./direct_io_test 4096
wait
echo -e "\n=== 4KB Direct I/O Test ==="
echo "Application writes:"
awk '/direct_io_test.APP_WRITE/ {sum+=$5; n++} END {print "  Count:", n, "Total:", sum}' page_direct.txt
echo "Device writes:"
awk '/DEVICE.BIO_SUBMIT/ {sum+=$5; n++} END {print "  Count:", n, "Total:", sum}' page_direct.txt
# Test 1MB write
sync; echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
./working_trace.sh 5 large_direct.txt &
sleep 1
./direct_io_test 1048576
awk '/DEVICE.*BIO_SUBMIT/ {sum+=$5; n++} END {print "  Count:", n, "Total:", sum}' large_direct.txtect.txt
[1] 59622
Starting tracer for 5 seconds...
Requested: 100 bytes, Written: 512 bytes
./working_trace.sh: line 9: 59624 Killed                  sudo ./build/multilayer_io_tracer -v > $OUTPUT 2>&1
Tracer stopped.
[1]+  Done                    ./working_trace.sh 5 small_direct.txt
=== 100-byte Direct I/O Test ===
Application writes:
  Count:  Total:
Device writes:
  Count: 459 Total: 1925120
[1] 59639
Starting tracer for 5 seconds...
Requested: 4096 bytes, Written: 4096 bytes
./working_trace.sh: line 9: 59641 Killed                  sudo ./build/multilayer_io_tracer -v > $OUTPUT 2>&1
Tracer stopped.
[1]+  Done                    ./working_trace.sh 5 page_direct.txt
=== 4KB Direct I/O Test ===
Application writes:
  Count:  Total:
Device writes:
  Count: 740 Total: 3043328
[1] 59656
Starting tracer for 5 seconds...
Requested: 1048576 bytes, Written: 1048576 bytes
./working_trace.sh: line 9: 59658 Killed                  sudo ./build/multilayer_io_tracer -v > $OUTPUT 2>&1
Tracer stopped.
[1]+  Done                    ./working_trace.sh 5 large_direct.txt
=== 1MB Direct I/O Test ===
Application writes:
  Count:  Total:
Device writes:
  Count: 1101 Total: 5607424
shwsun@zstore1:~/dev/io-efficiency-eBPF$ # Restore default dirty ratios (typical defaults)
echo 10 | sudo tee /proc/sys/vm/dirty_background_ratio
echo 20 | sudo tee /proc/sys/vm/dirty_ratio
10
20
```

#### Real-time Output
```
TIME                    SYSTEM   EVENT_TYPE   PID      TID      COMM            SIZE     OFFSET       LAT(us) RET
================================================================================
14:23:45.123456789     MinIO    SYSCALL_WRITE 12345    12345    minio           4096     0            45.23   4096
14:23:45.123500000     MinIO    VFS_WRITE     12345    12345    minio           4096     0            38.45   4096
14:23:45.123650000     MinIO    BLOCK_WRITE   12345    12345    minio           4096     2048         125.67  4096
```

#### Summary Output
```
=== I/O Amplification Summary ===
SYSTEM       SYS_R      SYS_W      VFS_R      VFS_W      BLK_R      BLK_W        R_AMP        W_AMP
================================================================================
MinIO           45        120        67        145        89        178         3.47         2.69
Ceph            23         85        78        234        95        267        10.65        5.85
etcd           156        89        234        156        267        189         3.21        2.75
```

## Analysis Features

### I/O Amplification Metrics

1. **Read Amplification**: `(VFS_reads + Block_reads) / Syscall_reads`
2. **Write Amplification**: `(VFS_writes + Block_writes) / Syscall_writes`
3. **Latency Analysis**: Average latency per operation type
4. **Throughput Analysis**: Bytes transferred per operation

### Visualizations Generated

1. **Amplification Comparison**: Bar charts comparing read/write amplification
2. **Operations Breakdown**: Syscall vs backend operations
3. **Latency Analysis**: Average latencies by system
4. **Efficiency Scatter**: Operations count vs amplification factor  
5. **Data Transfer**: Volume analysis across systems

### CSV Export Fields

- System name
- Read/Write amplification factors
- Operation counts (syscall, VFS, block)
- Byte counts (read/written)
- Average latencies
- Total operations

## Understanding Results

### Interpreting Amplification Factors

- **1.0x**: Perfect efficiency (no amplification)
- **2-3x**: Good efficiency (typical for well-designed systems)
- **5-10x**: Moderate amplification (room for optimization)
- **>10x**: High amplification (significant inefficiencies)

### Common Sources of Amplification

1. **Replication**: 3x minimum for triple-replicated systems
2. **Journaling**: Additional writes for consistency
3. **Metadata**: Filesystem and application metadata updates
4. **Coordination**: Consensus protocol overhead (Raft, Paxos)
5. **Layering**: Multiple abstraction layers

### Debugging High Amplification

1. **Check replication factor**: Is the baseline reasonable?
2. **Examine metadata overhead**: Are metadata operations excessive?
3. **Analyze coordination costs**: Is consensus protocol efficient?
4. **Review layering**: Can layers be bypassed or optimized?

## Troubleshooting

### Common Issues

1. **Permission denied**: Run with `sudo`
2. **BPF program failed to load**: Check kernel version (>=5.4) and BTF support
3. **No events captured**: Ensure target applications are running and generating I/O

### Verifying Installation

```bash
# Check kernel version
uname -r

# Check BTF support
ls /sys/kernel/btf/

# Test BPF program loading
make check

# Verify dependencies
bpftool version
clang --version
```

### Debug Mode

```bash
# Build with debug info
make debug

# Run with verbose output
sudo ./build/io_tracer -v

# Check BPF program loading
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## Research Applications

### Comparative Studies
- Cross-system efficiency analysis
- Impact of configuration changes
- Performance vs efficiency trade-offs

### Optimization Guidance
- Identify amplification sources
- Guide architectural decisions
- Validate optimization efforts

### Debugging Scenarios
- Performance regression analysis
- Unexpected I/O patterns
- Storage stack bottlenecks

## Contributing

### Adding New Storage Systems

1. Update the detection logic in `io_tracer.bpf.c`
2. Add new system type constants
3. Test with the new system
4. Update documentation

### Extending Analysis

1. Add new metrics to the analyzer
2. Create additional visualizations
3. Implement new export formats

## Limitations

1. **Kernel version dependency**: Requires Linux >=5.4 with BTF
2. **Root privileges**: eBPF programs require root access
3. **Overhead**: Minimal but measurable overhead during tracing
4. **Process name detection**: Simple string matching for system detection

## Future Enhancements

- [ ] Container-aware tracing
- [ ] Network I/O amplification
- [ ] Real-time alerting
- [ ] Web dashboard interface
- [ ] Integration with performance monitoring tools
- [ ] Support for more storage systems

## License

This project is licensed under the GPL-3.0 License - see the LICENSE file for details.

## Citation

If you use this tool in your research, please cite:

```bibtex
@misc{ebpf_io_tracer,
  title={eBPF I/O Amplification Tracer for Storage Systems},
  author={Your Name},
  year={2025},
  url={https://github.com/your-repo/ebpf-io-tracer}
}
```

## Related Work

- [Original APSys paper](your-paper-link)
- [FAST submission](your-submission-link)
- [BPF documentation](https://www.kernel.org/doc/html/latest/bpf/)
- [Storage system benchmarking](https://github.com/brianfrankcooper/YCSB)
