#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <size>\n", argv[0]);
        printf("  size: 100, 4096, or 1048576\n");
        return 1;
    }
    
    size_t size = atol(argv[1]);
    void *buf;
    
    // Allocate aligned buffer for O_DIRECT
    if (posix_memalign(&buf, 512, size < 512 ? 512 : size) != 0) {
        perror("posix_memalign");
        return 1;
    }
    memset(buf, 'A', size);
    
    // Open with O_DIRECT to bypass cache, O_SYNC for immediate write
    int fd = open("/tmp/direct_test.dat", 
                  O_CREAT | O_WRONLY | O_DIRECT | O_SYNC | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        free(buf);
        return 1;
    }
    
    // For sizes < 512, we need to write at least 512 bytes (O_DIRECT requirement)
    size_t write_size = size < 512 ? 512 : size;
    ssize_t written = write(fd, buf, write_size);
    
    printf("Requested: %zu bytes, Written: %zd bytes\n", size, written);
    
    close(fd);
    free(buf);
    unlink("/tmp/direct_test.dat");
    return 0;
}
