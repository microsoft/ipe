// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include <linux/fs.h>
#include <linux/types.h>
#include <linux/binfmts.h>
#include <linux/mman.h>
#include <linux/blk_types.h>
#include <linux/dm-verity.h>
#include <crypto/hash_info.h>

#include "ipe.h"
#include "hooks.h"
#include "eval.h"

/**
 * ipe_bprm_check_security - ipe security hook function for bprm check.
 * @bprm: Supplies a pointer to a linux_binprm structure to source the file
 *	  being evaluated.
 *
 * This LSM hook is called when a binary is loaded through the exec
 * family of system calls.
 * Return:
 * *0	- OK
 * *!0	- Error
 */
int ipe_bprm_check_security(struct linux_binprm *bprm)
{
	struct ipe_eval_ctx ctx = { 0 };

	build_eval_ctx(&ctx, bprm->file, __IPE_OP_EXEC);
	return ipe_evaluate_event(&ctx);
}

/**
 * ipe_mmap_file - ipe security hook function for mmap check.
 * @f: File being mmap'd. Can be NULL in the case of anonymous memory.
 * @reqprot: The requested protection on the mmap, passed from usermode.
 * @prot: The effective protection on the mmap, resolved from reqprot and
 *	  system configuration.
 * @flags: Unused.
 *
 * This hook is called when a file is loaded through the mmap
 * family of system calls.
 *
 * Return:
 * * 0	- OK
 * * !0	- Error
 */
int ipe_mmap_file(struct file *f, unsigned long reqprot, unsigned long prot,
		  unsigned long flags)
{
	struct ipe_eval_ctx ctx = { 0 };

	if (prot & PROT_EXEC) {
		build_eval_ctx(&ctx, f, __IPE_OP_EXEC);
		return ipe_evaluate_event(&ctx);
	}

	return 0;
}

/**
 * ipe_file_mprotect - ipe security hook function for mprotect check.
 * @vma: Existing virtual memory area created by mmap or similar.
 * @reqprot: The requested protection on the mmap, passed from usermode.
 * @prot: The effective protection on the mmap, resolved from reqprot and
 *	  system configuration.
 *
 * This LSM hook is called when a mmap'd region of memory is changing
 * its protections via mprotect.
 *
 * Return:
 * * 0	- OK
 * * !0	- Error
 */
int ipe_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
		      unsigned long prot)
{
	struct ipe_eval_ctx ctx = { 0 };

	/* Already Executable */
	if (vma->vm_flags & VM_EXEC)
		return 0;

	if (prot & PROT_EXEC) {
		build_eval_ctx(&ctx, vma->vm_file, __IPE_OP_EXEC);
		return ipe_evaluate_event(&ctx);
	}

	return 0;
}

/**
 * ipe_kernel_read_file - ipe security hook function for kernel read.
 * @file: Supplies a pointer to the file structure being read in from disk.
 * @id: Supplies the enumeration identifying the purpose of the read.
 * @contents: Unused.
 *
 * This LSM hook is called when a file is being read in from disk from
 * the kernel.
 *
 * Return:
 * 0 - OK
 * !0 - Error
 */
int ipe_kernel_read_file(struct file *file, enum kernel_read_file_id id,
			 bool contents)
{
	enum ipe_op_type op;
	struct ipe_eval_ctx ctx;

	switch (id) {
	case READING_FIRMWARE:
		op = __IPE_OP_FIRMWARE;
		break;
	case READING_MODULE:
		op = __IPE_OP_KERNEL_MODULE;
		break;
	case READING_KEXEC_INITRAMFS:
		op = __IPE_OP_KEXEC_INITRAMFS;
		break;
	case READING_KEXEC_IMAGE:
		op = __IPE_OP_KEXEC_IMAGE;
		break;
	case READING_POLICY:
		op = __IPE_OP_IMA_POLICY;
		break;
	case READING_X509_CERTIFICATE:
		op = __IPE_OP_IMA_X509;
		break;
	default:
		op = __IPE_OP_INVALID;
		WARN(op == __IPE_OP_INVALID, "no rule setup for enum %d", id);
	}

	build_eval_ctx(&ctx, file, op);
	return ipe_evaluate_event(&ctx);
}

/**
 * ipe_kernel_load_data - ipe security hook function for kernel load data.
 * @id: Supplies the enumeration identifying the purpose of the read.
 * @contents: Unused.
 *
 * This LSM hook is called when a buffer is being read in from disk.
 *
 * Return:
 * * 0	- OK
 * * !0	- Error
 */
int ipe_kernel_load_data(enum kernel_load_data_id id, bool contents)
{
	enum ipe_op_type op;
	struct ipe_eval_ctx ctx = { 0 };

	switch (id) {
	case LOADING_FIRMWARE:
		op = __IPE_OP_FIRMWARE;
		break;
	case LOADING_MODULE:
		op = __IPE_OP_KERNEL_MODULE;
		break;
	case LOADING_KEXEC_INITRAMFS:
		op = __IPE_OP_KEXEC_INITRAMFS;
		break;
	case LOADING_KEXEC_IMAGE:
		op = __IPE_OP_KEXEC_IMAGE;
		break;
	case LOADING_POLICY:
		op = __IPE_OP_IMA_POLICY;
		break;
	case LOADING_X509_CERTIFICATE:
		op = __IPE_OP_IMA_X509;
		break;
	default:
		op = __IPE_OP_INVALID;
		WARN(op == __IPE_OP_INVALID, "no rule setup for enum %d", id);
	}

	build_eval_ctx(&ctx, NULL, op);
	return ipe_evaluate_event(&ctx);
}

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

#ifdef CONFIG_IPE_PROP_DM_VERITY
/**
 * ipe_bdev_free_security - free IPE's LSM blob of block_devices.
 * @bdev: Supplies a pointer to a block_device that contains the structure
 *	  to free.
 */
void ipe_bdev_free_security(struct block_device *bdev)
{
	struct ipe_bdev *blob = ipe_bdev(bdev);

	kfree(blob->digest);
	kfree(blob->digest_algo);
}

/**
 * ipe_bdev_setsecurity - save data from a bdev to IPE's LSM blob.
 * @bdev: Supplies a pointer to a block_device that contains the LSM blob.
 * @key: Supplies the string key that uniquely identifies the value.
 * @value: Supplies the value to store.
 * @len: The length of @value.
 */
int ipe_bdev_setsecurity(struct block_device *bdev, const char *key,
			 const void *value, size_t len)
{
	struct ipe_bdev *blob = ipe_bdev(bdev);

	if (!strcmp(key, DM_VERITY_ROOTHASH_SEC_NAME)) {
		const struct dm_verity_digest *digest = value;

		blob->digest = kmemdup(digest->digest, digest->digest_len, GFP_KERNEL);
		if (!blob->digest)
			return -ENOMEM;

		blob->digest_algo = kstrdup_const(digest->algo, GFP_KERNEL);
		if (!blob->digest_algo)
			return -ENOMEM;

		blob->digest_len = digest->digest_len;
		return 0;
	} else if (!strcmp(key, DM_VERITY_SIGNATURE_SEC_NAME)) {
		blob->dm_verity_signed = true;
		return 0;
	}

	return -EOPNOTSUPP;
}
#endif /* CONFIG_IPE_PROP_DM_VERITY */
