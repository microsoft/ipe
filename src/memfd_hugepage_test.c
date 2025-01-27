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
    int errsv;
    char *addr;

    if (argc != 1)
    {
        fprintf(stderr, "Usage: memfd_hugepage_test\n");
        return EXIT_FAILURE;
    }

    fd = memfd_create("test_hugepage", MFD_HUGETLB);
    if (fd == -1)
    {
        fprintf(stderr, "ERROR: %s at %s, line %d\n", strerror(errno), __FILE__, __LINE__ - 3);
        goto err;
    }

    addr = mmap(NULL, 2 * 1024 * 1024, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED)
    {
        fprintf(stderr, "ERROR: %s at %s, line %d\n", strerror(errno), __FILE__, __LINE__ - 3);
        goto err;
    }

    munmap(addr, 2 * 1024 * 1024);
    exit(EXIT_SUCCESS);

err:
    errsv = errno;

    if (fd != -1)
        close(fd);

    exit(errsv);
}
