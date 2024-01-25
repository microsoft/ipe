/*
 * Integrity Policy Enforcement Test Suite
 * Copyright (C) Microsoft Corporation. All rights reserved.
 *
 */
#include <stdio.h>

__attribute__((constructor)) void init()
{
    printf("Hello World!\n");
}

void hello()
{
    printf("Hello World!\n");
}