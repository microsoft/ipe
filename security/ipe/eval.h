/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#ifndef _IPE_EVAL_H
#define _IPE_EVAL_H

#include <linux/file.h>
#include <linux/types.h>

#include "hooks.h"
#include "policy.h"

extern struct ipe_policy __rcu *ipe_active_policy;
extern bool success_audit;
extern bool enforce;

#ifdef CONFIG_IPE_PROP_DM_VERITY
struct ipe_bdev {
	bool dm_verity_signed;

	const u8 *digest;
	size_t digest_len;
	const char *digest_algo;
};
#endif /* CONFIG_IPE_PROP_DM_VERITY */

struct ipe_eval_ctx {
	enum ipe_op_type op;

	const struct file *file;
	bool from_init_sb;
#ifdef CONFIG_IPE_PROP_DM_VERITY
	const struct ipe_bdev *ipe_bdev;
#endif /* CONFIG_IPE_PROP_DM_VERITY */
};

enum ipe_match {
	__IPE_MATCH_RULE = 0,
	__IPE_MATCH_TABLE,
	__IPE_MATCH_GLOBAL,
	__IPE_MATCH_MAX
};

void build_eval_ctx(struct ipe_eval_ctx *ctx, const struct file *file, enum ipe_op_type op);
int ipe_evaluate_event(const struct ipe_eval_ctx *const ctx);
void ipe_invalidate_pinned_sb(const struct super_block *mnt_sb);

#endif /* _IPE_EVAL_H */
