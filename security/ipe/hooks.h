/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#ifndef _IPE_HOOKS_H
#define _IPE_HOOKS_H

#include <linux/fs.h>
#include <linux/binfmts.h>
#include <linux/security.h>
#include <linux/fsverity.h>
#include <linux/device-mapper.h>

int ipe_bprm_check_security(struct linux_binprm *bprm);

int ipe_mmap_file(struct file *f, unsigned long reqprot, unsigned long prot,
		  unsigned long flags);

int ipe_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
		      unsigned long prot);

int ipe_kernel_read_file(struct file *file, enum kernel_read_file_id id,
			 bool contents);

int ipe_kernel_load_data(enum kernel_load_data_id id, bool contents);

void ipe_sb_free_security(struct super_block *mnt_sb);

#ifdef CONFIG_IPE_PROP_DM_VERITY
void ipe_bdev_free_security(struct block_device *bdev);

int ipe_bdev_setsecurity(struct block_device *bdev, const char *key,
			 const void *value, size_t len);
#endif /* CONFIG_IPE_PROP_DM_VERITY */

#ifdef CONFIG_IPE_PROP_FS_VERITY
int ipe_inode_setsecurity(struct inode *inode, const char *name,
			  const void *value, size_t size,
			  int flags);
#endif /* CONFIG_IPE_PROP_FS_VERITY */

#endif /* _IPE_HOOKS_H */
