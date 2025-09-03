#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

int main() {
    int fd = open("/tmp/small_test.dat", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    char buf[100] = "X";
    
    // 100 separate 1-byte writes
    for(int i = 0; i < 100; i++) {
        write(fd, buf, 1);
    }
    
    fsync(fd);
    close(fd);
    return 0;
}
