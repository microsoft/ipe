/*
 * Integrity Policy Enforcement Test Suite
 * Copyright (C) Microsoft Corporation. All rights reserved.
 *
 */
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#define PAGE_SIZE 4096

int main(int argc, const char *argv[])
{
    int fd = -1;
    void *addr = NULL;
    const char *file_path;
    const char *option_args;
    struct stat sb;
    int prot = 0;
    int flag = 0;
    int errsv;
    int length;

    if (argc < 2 || argc > 3)
    {
        fprintf(stderr, "Usage: mmap_test options [file path]\n");
        return EXIT_FAILURE;
    }

    if (argc == 3)
    {
        file_path = argv[2];
        fd = open(file_path, O_RDONLY);
        if (fd == -1)
        {
            fprintf(stderr, "ERROR: %s at %s, line %d\n", strerror(errno), __FILE__, __LINE__ - 3);
            goto err;
        }

        if (-1 == fstat(fd, &sb))
        {
            fprintf(stderr, "ERROR: %s at %s, line %d\n", strerror(errno), __FILE__, __LINE__ - 2);
            goto err;
        }

        length = sb.st_size;
    }
    else
    {
        length = PAGE_SIZE;
        flag |= MAP_ANONYMOUS;
    }

    option_args = argv[1];
    if (strchr(option_args, 'r') != NULL)
        prot |= PROT_READ;
    if (strchr(option_args, 'w') != NULL)
        prot |= PROT_WRITE;
    if (strchr(option_args, 'x') != NULL)
        prot |= PROT_EXEC;
    if (strchr(option_args, 's') != NULL)
        flag |= MAP_SHARED;
    else
        flag |= MAP_PRIVATE;

    addr = mmap(NULL, length, prot, flag, fd, 0);
    if (addr == MAP_FAILED)
    {
        fprintf(stderr, "ERROR: %s at %s, line %d\n", strerror(errno), __FILE__, __LINE__ - 3);
        goto err;
    }

    if (fd != -1)
        close(fd);
    munmap(addr, length);

    return EXIT_SUCCESS;
err:
    errsv = errno;
    if (fd != -1)
        close(fd);

    if (addr != NULL && addr != MAP_FAILED)
        munmap(addr, length);

    return errsv;
}