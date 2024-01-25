/*
 * Integrity Policy Enforcement Test Suite
 * Copyright (C) Microsoft Corporation. All rights reserved.
 *
 */
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

int main(int argc, char *argv[])
{
    int fd = -1;
    int fd_source = -1;
    int errsv;
    char *source_path;
    ssize_t source_size;
    char *buf = NULL;
    ssize_t ret;
    struct stat sb;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: memfd_test file_path\n");
        return EXIT_FAILURE;
    }

    source_path = argv[1];
    fd_source = open(source_path, O_RDONLY);
    if (fd_source == -1)
    {
        fprintf(stderr, "ERROR: %s at %s, line %d\n", strerror(errno), __FILE__, __LINE__ - 3);
        goto err;
    }

    if (-1 == fstat(fd_source, &sb))
    {
        fprintf(stderr, "ERROR: %s at %s, line %d\n", strerror(errno), __FILE__, __LINE__ - 2);
        goto err;
    }
    source_size = sb.st_size;

    fd = memfd_create("test", 0);
    if (fd == -1)
    {
        fprintf(stderr, "ERROR: %s at %s, line %d\n", strerror(errno), __FILE__, __LINE__ - 3);
        goto err;
    }

    if (ftruncate(fd, source_size) == -1)
    {
        fprintf(stderr, "ERROR: %s at %s, line %d\n", strerror(errno), __FILE__, __LINE__ - 2);
        goto err;
    }

    buf = calloc(1, source_size);
    if (buf == NULL)
    {
        fprintf(stderr, "ERROR: %s at %s, line %d\n", strerror(errno), __FILE__, __LINE__ - 3);
        goto err;
    }

    ret = read(fd_source, buf, source_size);
    if (ret == -1)
    {
        fprintf(stderr, "ERROR: %s at %s, line %d\n", strerror(errno), __FILE__, __LINE__ - 3);
        goto err;
    }

    ret = write(fd, buf, source_size);
    if (ret == -1)
    {
        fprintf(stderr, "ERROR: %s at %s, line %d\n", strerror(errno), __FILE__, __LINE__ - 3);
        goto err;
    }

    char *env[] = {NULL};
    fexecve(fd, argv + 1, env);

err:
    errsv = errno;

    if (fd != -1)
        close(fd);
    if (fd_source != -1)
        close(fd_source);
    if (buf)
        free(buf);

    exit(errsv);
}
