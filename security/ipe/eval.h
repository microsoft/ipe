/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#ifndef _IPE_EVAL_H
#define _IPE_EVAL_H

#include <linux/file.h>
#include <linux/types.h>

#include "policy.h"

#define IPE_EVAL_CTX_INIT ((struct ipe_eval_ctx){ 0 })

extern struct ipe_policy __rcu *ipe_active_policy;

#ifdef CONFIG_BLK_DEV_INITRD
struct ipe_sb {
	bool is_initramfs;
};
#endif /* CONFIG_BLK_DEV_INITRD */

struct ipe_eval_ctx {
	enum ipe_op_type op;

	const struct file *file;
#ifdef CONFIG_BLK_DEV_INITRD
	bool from_initramfs;
#endif /* CONFIG_BLK_DEV_INITRD */
};

void build_eval_ctx(struct ipe_eval_ctx *ctx, const struct file *file, enum ipe_op_type op);
int ipe_evaluate_event(const struct ipe_eval_ctx *const ctx);

#endif /* _IPE_EVAL_H */
