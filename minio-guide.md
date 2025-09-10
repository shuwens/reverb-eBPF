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




