/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#ifndef _IPE_EVAL_H
#define _IPE_EVAL_H

#include <linux/file.h>
#include <linux/types.h>

#include "policy.h"
#include "hooks.h"

#define IPE_EVAL_CTX_INIT ((struct ipe_eval_ctx){ 0 })

extern struct ipe_policy __rcu *ipe_active_policy;
extern bool success_audit;
extern bool enforce;

#ifdef CONFIG_BLK_DEV_INITRD
struct ipe_sb {
	bool is_initramfs;
};
#endif /* CONFIG_BLK_DEV_INITRD */

#ifdef CONFIG_IPE_PROP_DM_VERITY
struct ipe_bdev {
	bool dm_verity_signed;
	struct digest_info *root_hash;
};
#endif /* CONFIG_IPE_PROP_DM_VERITY */

struct ipe_eval_ctx {
	enum ipe_op_type op;
	enum ipe_hook_type hook;

	const struct file *file;
#ifdef CONFIG_BLK_DEV_INITRD
	bool from_initramfs;
#endif /* CONFIG_BLK_DEV_INITRD */
#ifdef CONFIG_IPE_PROP_DM_VERITY
	const struct ipe_bdev *ipe_bdev;
#endif /* CONFIG_IPE_PROP_DM_VERITY */
};

enum ipe_match {
	IPE_MATCH_RULE = 0,
	IPE_MATCH_TABLE,
	IPE_MATCH_GLOBAL,
	__IPE_MATCH_MAX
};

void build_eval_ctx(struct ipe_eval_ctx *ctx, const struct file *file,
		    enum ipe_op_type op, enum ipe_hook_type hook);
int ipe_evaluate_event(const struct ipe_eval_ctx *const ctx);

#endif /* _IPE_EVAL_H */
