# MinIO experiment Getting Started Guide

## Install and setup MinIO

Follow this [MinIO
guide](https://docs.min.io/community/minio-object-store/operations/deployments/baremetal-deploy-minio-on-ubuntu-linux.html).
It should not be hard to finish.

Note that you need to have the SSDs mounted already, as `/mnt/minio1` in this
example. To do so, run things like this
```bash
# figure out the devices
nvme list
# or 
lspci -vv | grep NVMe


# Format the device if you need to 
# For ext4
sudo mkfs.ext4 /dev/nvme1n1
# For XFS
sudo mkfs.xfs /dev/nvme1n1

# mount SSD
sudo mount /dev/nvme1n1 /mnt/minio1

# To start MinIO
sudo ./run_minio.sh
```

## Run workload
We choose S3 as the interface to do read/write to MinIO
```bash
[17:42] zstore2:reverb-eBPF (main %) | aws configure --profile minio
AWS Access Key ID [None]: minioadmin
AWS Secret Access Key [None]: admin123
Default region name [None]:
Default output format [None]:
```
Now you can interact with MinIO using S3 API:
```bash
[17:48] zstore2:reverb-eBPF (main %) | aws s3api create-bucket --bucket public --profile minio
{
    "Location": "/public"
}
[17:49] zstore2:reverb-eBPF (main %) | aws s3 ls --profile minio
2025-09-10 17:49:03 public
```

## Tracing with MinIO
### Basic MinIO Tracing
# Auto-detect and trace all MinIO processes
sudo ./multilayer_io_tracer -A -v

# Trace specific MinIO PID
MINIO_PID=$(pgrep minio)
sudo ./multilayer_io_tracer -p $MINIO_PID -v


### Advanced MinIO Analysis
# Full MinIO analysis with correlation
sudo ./multilayer_io_tracer -M -c -E -T -v -o minio_analysis.log

# Trace MinIO with real-time output
sudo ./multilayer_io_tracer -A -E -T

# JSON output for parsing
sudo ./multilayer_io_tracer -M -j -o minio_trace.json

### MinIO with Specific Features
# Track erasure coding overhead
sudo ./multilayer_io_tracer -M -E -c

# Track metadata operations only
sudo ./multilayer_io_tracer -M -T

# Time-limited tracing (60 seconds)
sudo ./multilayer_io_tracer -A -d 60 -o minio_60s.log
