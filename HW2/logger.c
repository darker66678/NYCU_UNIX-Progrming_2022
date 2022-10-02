#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdarg.h>

FILE *output = NULL;
char path[128];
char link_new[128];
char filename[128];
char s_buf[32];

void get_dlsym(void **func_ptr, const char *name)
{
    *func_ptr = dlsym(RTLD_NEXT, name);
}
void get_output()
{
    char *file = getenv("OUTPUT_FILE");
    if (strcmp(file, "default") == 0)
    {
        int fd = dup(fileno(stderr));
        output = fdopen(fd, "w");
    }
    else
    {
        int fd = dup(fileno(stderr));
        FILE *link_new = fdopen(fd, "w");
        output = freopen(file, "w+", link_new);
    }
}

void buf_check(char *s_buf, char *buf, ssize_t r)
{
    for (int i = 0; i < r; i++)
    {
        if (i >= 32)
        {
            break;
        }
        int res = isprint(buf[i]);
        if (res)
        {
            s_buf[i] = buf[i];
        }
        else
        {
            s_buf[i] = '.';
        }
    }
}

void file_ptr_path(char *filename, FILE *stream)
{
    int fno = fileno(stream);
    pid_t pid = getpid();
    sprintf(link_new, "/proc/%d/fd/%d", pid, fno);
    ssize_t r = readlink(link_new, filename, 128);
    filename[r] = '\0';
    memset(link_new, 0, 128);
}

int chmod(const char *pathname, mode_t mode)
{
    int (*chmod_original)(const char *pathname, mode_t mode) = NULL;
    int res;
    if (chmod_original == NULL)
    {
        get_dlsym((void **)&chmod_original, "chmod");
        if (!output)
        {
            get_output();
        }
        res = chmod_original(pathname, mode);
        char *result = realpath(pathname, path);
        if (result == NULL)
        {
            fprintf(output, "[logger] chmod(\"%s\", %o) = %d\n", pathname, mode, res);
        }
        else
        {
            fprintf(output, "[logger] chmod(\"%s\", %o) = %d\n", result, mode, res);
        }
        fflush(output);
        memset(path, 0, 128);
    }
    return res;
}

int chown(const char *pathname, uid_t owner, gid_t group)
{
    int (*chown_original)(const char *pathname, uid_t owner, gid_t group) = NULL;
    int res;
    if (chown_original == NULL)
    {
        get_dlsym((void **)&chown_original, "chown");
        if (!output)
        {
            get_output();
        }
        res = chown_original(pathname, owner, group);
        char *result = realpath(pathname, path);
        if (result == NULL)
        {
            fprintf(output, "[logger] chown(\"%s\", %d, %d) = %d\n", pathname, owner, group, res);
        }
        else
        {
            fprintf(output, "[logger] chown(\"%s\", %d, %d) = %d\n", result, owner, group, res);
        }
        fflush(output);
        memset(path, 0, 128);
    }
    return res;
}

int close(int fd)
{
    int (*close_original)(int fd) = NULL;
    int res;
    pid_t pid = getpid();
    if (close_original == NULL)
    {
        get_dlsym((void **)&close_original, "close");
        if (!output)
        {
            get_output();
        }
        sprintf(link_new, "/proc/%d/fd/%d", pid, fd);
        ssize_t r = readlink(link_new, filename, sizeof(filename) - 1);
        filename[r] = '\0';
        res = close_original(fd);
        fprintf(output, "[logger] close(\"%s\") = %d\n", filename, res);
        fflush(output);
        memset(filename, 0, 128);
        memset(link_new, 0, 128);
    }
    return res;
}

int creat(const char *pathname, mode_t mode)
{
    int (*creat_original)(const char *pathname, mode_t mode) = NULL;
    int res;

    if (creat_original == NULL)
    {
        get_dlsym((void **)&creat_original, "creat");
        if (!output)
        {
            get_output();
        }
        res = creat_original(pathname, mode);
        char *result = realpath(pathname, path);
        if (result == NULL)
        {

            fprintf(output, "[logger] creat(\"%s\", %o) = %d\n", pathname, mode, res);
        }
        else
        {

            fprintf(output, "[logger] creat(\"%s\", %o) = %d\n", result, mode, res);
        }
        fflush(output);
        memset(path, 0, 128);
    }
    return res;
}

int fclose(FILE *stream)
{
    int (*fclose_original)(FILE * stream) = NULL;
    int res;
    if (fclose_original == NULL)
    {
        get_dlsym((void **)&fclose_original, "fclose");
        if (!output)
        {
            get_output();
        }
        file_ptr_path(filename, stream);
        res = fclose_original(stream);

        fprintf(output, "[logger] fclose(\"%s\") = %d\n", filename, res);
        fflush(output);
        memset(filename, 0, 128);
    }
    return res;
}

FILE *fopen(const char *filename, const char *mode)
{
    FILE *(*fopen_original)(const char *filename, const char *mode) = NULL;
    FILE *res;

    if (fopen_original == NULL)
    {
        get_dlsym((void **)&fopen_original, "fopen");
        if (!output)
        {
            get_output();
        }
        res = fopen_original(filename, mode);
        char *res = realpath(filename, path);
        if (res == NULL)
        {

            fprintf(output, "[logger] fopen(\"%s\", \"%s\") = %p\n", filename, mode, res);
        }
        else
        {

            fprintf(output, "[logger] fopen(\"%s\", \"%s\") = %p\n", path, mode, res);
        }
        fflush(output);
        memset(path, 0, 128);
    }
    return res;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    size_t (*fread_original)(void *ptr, size_t size, size_t nmemb, FILE *stream) = NULL;
    size_t res;
    if (fread_original == NULL)
    {
        get_dlsym((void **)&fread_original, "fread");
        if (!output)
        {
            get_output();
        }
        file_ptr_path(filename, stream);
        res = fread_original(ptr, size, nmemb, stream);
        buf_check(s_buf, (char *)ptr, res);

        fprintf(output, "[logger] fread(\"%s\", %ld, %ld, \"%s\") = %ld\n", s_buf, size, nmemb, filename, res);
        fflush(output);
        memset(s_buf, 0, 32);
        memset(filename, 0, 128);
    }
    return res;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    size_t (*fwrite_original)(const void *ptr, size_t size, size_t nmemb, FILE *stream) = NULL;
    size_t res;
    if (fwrite_original == NULL)
    {
        get_dlsym((void **)&fwrite_original, "fwrite");
        if (!output)
        {
            get_output();
        }
        file_ptr_path(filename, stream);
        res = fwrite_original(ptr, size, nmemb, stream);

        buf_check(s_buf, (char *)ptr, res);
        fprintf(output, "[logger] fwrite(\"%s\", %ld, %ld, \"%s\") = %ld\n", s_buf, size, nmemb, filename, res);
        fflush(output);
        memset(s_buf, 0, 32);
        memset(filename, 0, 128);
    }
    return res;
}

int open(const char *pathname, int flags, ...)
{
    int mode = 0;
    if (__OPEN_NEEDS_MODE(flags))
    {
        va_list arg;
        va_start(arg, flags);
        mode = va_arg(arg, int);
        va_end(arg);
    }

    int (*open_original)(const char *pathname, int flags, ...) = NULL;
    int res;

    if (open_original == NULL)
    {
        get_dlsym((void **)&open_original, "open");
        if (!output)
        {
            get_output();
        }
        res = open_original(pathname, flags, mode);
        char *result = realpath(pathname, path);
        if (result == NULL)
        {
            fprintf(output, "[logger] open(\"%s\", %03o, %03o) = %d\n", pathname, flags, mode, res);
        }
        else
        {

            fprintf(output, "[logger] open(\"%s\", %03o, %03o) = %d\n", result, flags, mode, res);
        }
        fflush(output);
        memset(path, 0, 128);
    }
    return res;
}

ssize_t read(int fd, void *buf, size_t count)
{
    ssize_t (*read_original)(int fd, void *buf, size_t count) = NULL;
    ssize_t res;
    pid_t pid = getpid();
    if (read_original == NULL)
    {
        get_dlsym((void **)&read_original, "read");
        if (!output)
        {
            get_output();
        }
        sprintf(link_new, "/proc/%d/fd/%d", pid, fd);
        ssize_t r = readlink(link_new, filename, sizeof(filename) - 1);
        filename[r] = '\0';
        res = read_original(fd, buf, count);
        buf_check(s_buf, (char *)buf, res);

        fprintf(output, "[logger] read(\"%s\", \"%s\", %ld) = %ld\n", filename, s_buf, count, res);
        fflush(output);
        memset(s_buf, 0, 32);
        memset(filename, 0, 128);
        memset(link_new, 0, 128);
    }
    return res;
}

int remove(const char *pathname)
{
    int (*remove_original)(const char *pathname) = NULL;
    int res;

    if (remove_original == NULL)
    {
        get_dlsym((void **)&remove_original, "remove");
        if (!output)
        {
            get_output();
        }
        char *result = realpath(pathname, path);
        res = remove_original(pathname);
        if (result == NULL)
        {
            fprintf(output, "[logger] remove(\"%s\") = %d\n", pathname, res);
        }
        else
        {
            fprintf(output, "[logger] remove(\"%s\") = %d\n", result, res);
        }
        fflush(output);
        memset(path, 0, 128);
    }
    return res;
}

int rename(const char *oldpath, const char *newpath)
{
    int (*rename_original)(const char *oldpath, const char *newpath) = NULL;
    int res;
    char old_path[128];
    char new_path[128];
    if (rename_original == NULL)
    {
        get_dlsym((void **)&rename_original, "rename");
        if (!output)
        {
            get_output();
        }
        char *result = realpath(oldpath, old_path);
        res = rename_original(oldpath, newpath);
        if (result == NULL)
        {
            char *new_result = realpath(newpath, new_path);
            if (new_result == NULL)
            {

                fprintf(output, "[logger] rename(\"%s\", \"%s\") = %d\n", oldpath, newpath, res);
            }
            else
            {

                fprintf(output, "[logger] rename(\"%s\", \"%s\") = %d\n", oldpath, new_result, res);
            }
        }
        else
        {
            char *new_result = realpath(newpath, new_path);
            if (new_result == NULL)
            {

                fprintf(output, "[logger] rename(\"%s\", \"%s\") = %d\n", result, newpath, res);
            }
            else
            {

                fprintf(output, "[logger] rename(\"%s\", \"%s\") = %d\n", result, new_result, res);
            }
        }
        fflush(output);
        memset(old_path, 0, 128);
        memset(new_path, 0, 128);
    }
    return res;
}

FILE *tmpfile(void)
{
    FILE *(*tmpfile_original)(void) = NULL;
    FILE *res;
    if (tmpfile_original == NULL)
    {
        get_dlsym((void **)&tmpfile_original, "tmpfile");
        if (!output)
        {
            get_output();
        }
        res = tmpfile_original();

        fprintf(output, "[logger] tmpfile() = %p\n", res);
        fflush(output);
    }
    return res;
}

ssize_t write(int fd, const void *buf, size_t count)
{
    ssize_t (*write_original)(int fd, const void *buf, size_t count) = NULL;
    ssize_t res;
    pid_t pid = getpid();
    if (write_original == NULL)
    {
        get_dlsym((void **)&write_original, "write");
        if (!output)
        {
            get_output();
        }
        sprintf(link_new, "/proc/%d/fd/%d", pid, fd);
        ssize_t r = readlink(link_new, filename, sizeof(filename) - 1);
        filename[r] = '\0';
        res = write_original(fd, buf, count);
        buf_check(s_buf, (char *)buf, res);

        fprintf(output, "[logger] write(\"%s\", \"%s\", %ld) = %ld\n", filename, s_buf, count, res);
        fflush(output);
        memset(s_buf, 0, 32);
        memset(filename, 0, 128);
        memset(link_new, 0, 128);
    }
    return res;
}