// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include <linux/fs.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>

#include "ipe.h"
#include "eval.h"
#include "hooks.h"
#include "policy.h"

struct ipe_policy __rcu *ipe_active_policy;

static struct super_block *pinned_sb;
static DEFINE_SPINLOCK(pin_lock);
#define FILE_SUPERBLOCK(f) ((f)->f_path.mnt->mnt_sb)

/**
 * pin_sb - Pin the underlying superblock of @f, marking it as trusted.
 * @f: Supplies a file structure to source the super_block from.
 */
static void pin_sb(const struct file *f)
{
	if (!f)
		return;
	spin_lock(&pin_lock);
	if (pinned_sb)
		goto out;
	pinned_sb = FILE_SUPERBLOCK(f);
out:
	spin_unlock(&pin_lock);
}

/**
 * from_pinned - Determine whether @f is source from the pinned super_block.
 * @f: Supplies a file structure to check against the pinned super_block.
 *
 * Return:
 * * true	- @f is sourced from the pinned super_block
 * * false	- @f is not sourced from the pinned super_block
 */
static bool from_pinned(const struct file *f)
{
	bool rv;

	if (!f)
		return false;
	spin_lock(&pin_lock);
	rv = !IS_ERR_OR_NULL(pinned_sb) && pinned_sb == FILE_SUPERBLOCK(f);
	spin_unlock(&pin_lock);
	return rv;
}

/**
 * build_eval_ctx - Build an evaluation context.
 * @ctx: Supplies a pointer to the context to be populdated.
 * @file: Supplies a pointer to the file to associated with the evaluation.
 * @op: Supplies the IPE policy operation associated with the evaluation.
 */
void build_eval_ctx(struct ipe_eval_ctx *ctx,
		    const struct file *file,
		    enum ipe_op_type op)
{
	struct inode *ino = NULL;

	if (op == __IPE_OP_EXEC)
		pin_sb(file);

	ctx->file = file;
	ctx->op = op;
	ctx->from_init_sb = from_pinned(file);
}

/**
 * evaluate_property - Analyze @ctx against a property.
 * @ctx: Supplies a pointer to the context to be evaluated.
 * @p: Supplies a pointer to the property to be evaluated.
 *
 * Return:
 * * true	- The current @ctx match the @p
 * * false	- The current @ctx doesn't match the @p
 */
static bool evaluate_property(const struct ipe_eval_ctx *const ctx,
			      struct ipe_prop *p)
{
	bool eval = false;

	switch (p->type) {
	case __IPE_PROP_BOOT_VERIFIED_FALSE:
		eval = !ctx->from_init_sb;
		break;
	case __IPE_PROP_BOOT_VERIFIED_TRUE:
		eval = ctx->from_init_sb;
		break;
	default:
		eval = false;
	}

	return eval;
}

/**
 * ipe_evaluate_event - Analyze @ctx against the current active policy.
 * @ctx: Supplies a pointer to the context to be evaluated.
 *
 * This is the loop where all policy evaluation happens against IPE policy.
 *
 * Return:
 * * 0		- OK
 * * -EACCES	- @ctx did not pass evaluation.
 * * !0		- Error
 */
int ipe_evaluate_event(const struct ipe_eval_ctx *const ctx)
{
	int rc = 0;
	bool match = false;
	enum ipe_action_type action;
	struct ipe_policy *pol = NULL;
	const struct ipe_rule *rule = NULL;
	const struct ipe_op_table *rules = NULL;
	struct ipe_prop *prop = NULL;

	pol = ipe_get_policy_rcu(ipe_active_policy);
	if (!pol)
		goto out;

	if (ctx->op == __IPE_OP_MAX) {
		action = pol->parsed->global_default_action;
		goto eval;
	}

	rules = &pol->parsed->rules[ctx->op];

	list_for_each_entry(rule, &rules->rules, next) {
		match = true;

		list_for_each_entry(prop, &rule->props, next)
			match = match && evaluate_property(ctx, prop);

		if (match)
			break;
	}

	if (match)
		action = rule->action;
	else if (rules->default_action != ipe_action_max)
		action = rules->default_action;
	else
		action = pol->parsed->global_default_action;

eval:
	if (action == __IPE_ACTION_DENY)
		rc = -EACCES;

out:
	return rc;
}

/**
 * ipe_invalidate_pinned_sb - invalidate the ipe pinned super_block.
 * @mnt_sb: super_block to check against the pinned super_block.
 *
 * This function is called a super_block like the initramfs's is freed,
 * if the super_block is currently pinned by ipe it will be invalided,
 * so ipe won't consider the block device is boot verified afterward.
 */
void ipe_invalidate_pinned_sb(const struct super_block *mnt_sb)
{
	spin_lock(&pin_lock);

	if (!IS_ERR_OR_NULL(pinned_sb) && mnt_sb == pinned_sb)
		pinned_sb = ERR_PTR(-EIO);

	spin_unlock(&pin_lock);
}
