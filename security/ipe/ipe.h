/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#ifndef _IPE_H
#define _IPE_H

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) "IPE: " fmt

#include <linux/lsm_hooks.h>
#ifdef CONFIG_BLK_DEV_INITRD
struct ipe_sb *ipe_sb(const struct super_block *sb);
#endif /* CONFIG_BLK_DEV_INITRD */

extern bool ipe_enabled;

#ifdef CONFIG_IPE_PROP_DM_VERITY
struct ipe_bdev *ipe_bdev(struct block_device *b);
#endif /* CONFIG_IPE_PROP_DM_VERITY */
#ifdef CONFIG_IPE_PROP_FS_VERITY
struct ipe_inode *ipe_inode(const struct inode *inode);
#endif /* CONFIG_IPE_PROP_FS_VERITY */

#endif /* _IPE_H */
