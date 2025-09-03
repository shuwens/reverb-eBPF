#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main() {
    printf("Starting amplification test\n");
    
    // Test 1: Single 100-byte write
    int fd = open("/tmp/test_100.dat", O_CREAT | O_WRONLY | O_SYNC, 0644);
    char small_buf[100];
    memset(small_buf, 'A', 100);
    write(fd, small_buf, 100);
    close(fd);
    
    // Test 2: Single 4KB write  
    fd = open("/tmp/test_4k.dat", O_CREAT | O_WRONLY | O_SYNC, 0644);
    char medium_buf[4096];
    memset(medium_buf, 'B', 4096);
    write(fd, medium_buf, 4096);
    close(fd);
    
    // Test 3: Single 1MB write
    fd = open("/tmp/test_1m.dat", O_CREAT | O_WRONLY | O_SYNC, 0644);
    char *large_buf = malloc(1048576);
    memset(large_buf, 'C', 1048576);
    write(fd, large_buf, 1048576);
    free(large_buf);
    close(fd);
    
    printf("Test complete\n");
    return 0;
}
