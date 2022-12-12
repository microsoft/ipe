// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include "ipe.h"
#include "hooks.h"

bool ipe_enabled;

static struct lsm_blob_sizes ipe_blobs __lsm_ro_after_init = {
};

static struct security_hook_list ipe_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(sb_free_security, ipe_sb_free_security),
	LSM_HOOK_INIT(bprm_check_security, ipe_bprm_check_security),
	LSM_HOOK_INIT(mmap_file, ipe_mmap_file),
	LSM_HOOK_INIT(file_mprotect, ipe_file_mprotect),
	LSM_HOOK_INIT(kernel_read_file, ipe_kernel_read_file),
	LSM_HOOK_INIT(kernel_load_data, ipe_kernel_load_data),
};

/**
 * ipe_init - Entry point of IPE.
 *
 * This is called at LSM init, which happens occurs early during kernel
 * start up. During this phase, IPE loads the properties compiled into
 * the kernel, and register's IPE's hooks. The boot policy is loaded
 * later, during securityfs init, at which point IPE will start
 * enforcing its policy.
 *
 * Return:
 * * 0		- OK
 * * -ENOMEM	- Context creation failed.
 */
static int __init ipe_init(void)
{
	int rc = 0;

	security_add_hooks(ipe_hooks, ARRAY_SIZE(ipe_hooks), "ipe");
	ipe_enabled = true;

	return rc;
}

DEFINE_LSM(ipe) = {
	.name = "ipe",
	.init = ipe_init,
	.blobs = &ipe_blobs,
};
