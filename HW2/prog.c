#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

int main() {
    int fd;
    if ((fd = creat("creat.txt", 0666)) == -1) {
        perror("creat error\n");
    }
    if (lseek(fd, 128, SEEK_SET) == -1) {
        perror("creat error\n");
    }
    char writebuffer[] = "cccc.";
    char readbuffer[32] = {0};
    memset((void*)readbuffer, 0, sizeof(readbuffer));
    if (write(fd, writebuffer, strlen(writebuffer)) == -1) {
        perror("write error\n");
    }
    if (close(fd) == -1) {
        perror("close failed\n");
    }
    if ((fd = open("creat.txt", 0666)) == -1) {
        perror("open error\n");
    }
    if (read(fd, readbuffer, 100) == -1) {
        fprintf(stderr, "errno : %s\n",strerror(errno));
        perror("read error\n");
    }
    if (close(fd) == -1) {
        perror("close failed\n");
    }
    // printf("buffer : %s\n", readbuffer);

    mode_t mode = 0770;
    if (chmod("creat.txt", mode) == -1) {
        perror("chmod error\n");
    }
    uid_t uid = -1;
    gid_t gid = -1;
    if (chown("creat.txt", uid, gid) == -1) {
        perror("chown error\n");
    }
    if (rename("creat.txt", "create.txt") == -1) {
        perror("rename error\n");
    }
    FILE* fp;
    if ((fp = fopen("create.txt", "a+")) == NULL) {
        perror("fopen error\n");
    }
    memset((void*)readbuffer, 0, sizeof(readbuffer));
    if (fread(readbuffer, sizeof(char), 10, fp) == -1) {
        perror("fread error\n");
    }
    if (fwrite(writebuffer, sizeof(char), 10, fp) == -1) {
        perror("fwrite error\n");
    }
    if (fclose(fp) == -1) {
        perror("fclose error\n");
    }
    if (remove("create.txt") == -1) {
        perror("remove failed\n");
    }
    if ((fp = tmpfile()) == NULL) {
        perror("tmpfile failed\n");
    }
    if (fclose(fp) == -1) {
        perror("fclose error\n");
    }
    return 0;
}