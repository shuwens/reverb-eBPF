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

### 3. IO Tracer Usage

```bash
# Real-time tracing (requires root)
sudo ./build/io_tracer -v -d 30

# JSON output for analysis
sudo ./build/io_tracer -j -d 60 -o trace.json

# Quiet mode with summary only
sudo ./build/io_tracer -q -d 10
```

### multi layer tracer usage 
```bash
# Basic tracing with real-time output
sudo ./multilayer_io_tracer

# Trace specific storage system with correlation
sudo ./multilayer_io_tracer -c -s minio

# Quiet mode with summary only
sudo ./multilayer_io_tracer -q -d 60

# JSON output for analysis
sudo ./multilayer_io_tracer -j -o trace.json

# Verbose mode with correlation
sudo ./multilayer_io_tracer -v -c
```


### 4. Analyze Results

```bash
# Basic analysis
python3 analyze_io.py trace.json

# Generate visualizations
python3 analyze_io.py trace.json -v -o plots/

# Export to CSV
python3 analyze_io.py trace.json -e results.csv -v
```

## Detailed Usage

### eBPF Tracer Options

```bash
./build/io_tracer [OPTIONS]

Options:
  -v, --verbose     Enable verbose debug output
  -j, --json        Output events in JSON format
  -d, --duration N  Trace for N seconds (default: infinite)
  -o, --output FILE Write output to file instead of stdout
  -q, --quiet       Disable real-time output, show summary only
```

### Example Workflows

#### 1. MinIO Analysis
```bash
# Start MinIO server
minio server /data &

# Trace MinIO operations
sudo ./build/io_tracer -j -d 60 -o minio_trace.json

# In another terminal, run workload
mc cp largefile.dat minio/bucket/

# Analyze results
python3 analyze_io.py minio_trace.json -v -e minio_results.csv
```

#### 2. Ceph Analysis
```bash
# Ensure Ceph cluster is running
sudo systemctl start ceph-mon@$(hostname)
sudo systemctl start ceph-mgr@$(hostname)
sudo systemctl start ceph-osd@*

# Trace Ceph operations
sudo ./build/io_tracer -j -d 120 -o ceph_trace.json

# Run RADOS bench
rados bench -p mypool 60 write

# Analyze results
python3 analyze_io.py ceph_trace.json -v
```

#### 3. etcd Analysis
```bash
# Start etcd
etcd --data-dir=/tmp/etcd-data &

# Trace etcd operations
sudo ./build/io_tracer -j -d 30 -o etcd_trace.json

# Run etcd workload
for i in {1..1000}; do
  etcdctl put key$i value$i
done

# Analyze results
python3 analyze_io.py etcd_trace.json -v -o etcd_plots/
```

### Expected Output

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
