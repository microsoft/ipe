// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include <linux/fs.h>
#include <linux/types.h>
#include <linux/binfmts.h>
#include <linux/mman.h>

#include "ipe.h"
#include "hooks.h"
#include "eval.h"

/**
 * ipe_sb_free_security - ipe security hook function for super_block.
 * @mnt_sb: Supplies a pointer to a super_block is about to be freed.
 *
 * IPE does not have any structures with mnt_sb, but uses this hook to
 * invalidate a pinned super_block.
 */
void ipe_sb_free_security(struct super_block *mnt_sb)
{
	ipe_invalidate_pinned_sb(mnt_sb);
}
