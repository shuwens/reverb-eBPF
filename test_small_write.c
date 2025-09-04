#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int main() {
    int fd = open("small.dat", O_CREAT | O_WRONLY | O_SYNC, 0644);
    char buf[100];
    memset(buf, 'A', 100);
    write(fd, buf, 100);  // Write only 100 bytes
    fsync(fd);
    close(fd);
    unlink("small.dat");
    return 0;
}
