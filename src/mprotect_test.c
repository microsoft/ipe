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

int extract_prot(const char *prot_args)
{
    int ret = 0;
    if (strchr(prot_args, 'r') != NULL)
        ret |= PROT_READ;
    if (strchr(prot_args, 'w') != NULL)
        ret |= PROT_WRITE;
    if (strchr(prot_args, 'x') != NULL)
        ret |= PROT_EXEC;

    return ret;
}

int main(int argc, const char *argv[])
{
    int fd = -1;
    void *addr = NULL;
    const char *file_path;
    struct stat sb;
    int prot_before = 0;
    int prot_after = 0;
    int length;
    int errsv;

    if (argc != 4)
    {
        fprintf(stderr, "Usage: mprotect_test prot_before prot_after file_path\n");
        return EXIT_FAILURE;
    }

    file_path = argv[3];
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
    prot_before = extract_prot(argv[1]);
    prot_after = extract_prot(argv[2]);

    addr = mmap(NULL, length, prot_before, MAP_PRIVATE, fd, 0);
    if (addr == MAP_FAILED)
    {
        fprintf(stderr, "ERROR: %s at %s, line %d\n", strerror(errno), __FILE__, __LINE__ - 3);
        goto err;
    }

    if (-1 == mprotect(addr, length, prot_after))
    {
        fprintf(stderr, "ERROR: %s at %s, line %d\n", strerror(errno), __FILE__, __LINE__ - 2);
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