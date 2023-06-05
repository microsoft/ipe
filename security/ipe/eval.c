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

static const struct super_block *pinned_sb;
static DEFINE_SPINLOCK(pin_lock);
#define FILE_SUPERBLOCK(f) ((f)->f_path.mnt->mnt_sb)

/**
 * pin_sb - Pin the underlying superblock of @f, marking it as trusted.
 * @sb: Supplies a super_block structure to be pinned.
 */
static void pin_sb(const struct super_block *sb)
{
	if (!sb)
		return;
	spin_lock(&pin_lock);
	if (!pinned_sb)
		pinned_sb = sb;
	spin_unlock(&pin_lock);
}

/**
 * from_pinned - Determine whether @sb is the pinned super_block.
 * @sb: Supplies a super_block to check against the pinned super_block.
 *
 * Return:
 * * true	- @sb is the pinned super_block
 * * false	- @sb is not the pinned super_block
 */
static bool from_pinned(const struct super_block *sb)
{
	bool rv;

	if (!sb)
		return false;
	spin_lock(&pin_lock);
	rv = !IS_ERR_OR_NULL(pinned_sb) && pinned_sb == sb;
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
	if (op == __IPE_OP_EXEC && file)
		pin_sb(FILE_SUPERBLOCK(file));

	ctx->file = file;
	ctx->op = op;

	if (file)
		ctx->from_init_sb = from_pinned(FILE_SUPERBLOCK(file));
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
	switch (p->type) {
	case __IPE_PROP_BOOT_VERIFIED_FALSE:
		return !ctx->from_init_sb;
	case __IPE_PROP_BOOT_VERIFIED_TRUE:
		return ctx->from_init_sb;
	default:
		return false;
	}
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

	rcu_read_lock();

	pol = rcu_dereference(ipe_active_policy);
	if (!pol) {
		rcu_read_unlock();
		return 0;
	}

	if (ctx->op == __IPE_OP_INVALID) {
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
	else if (rules->default_action != __IPE_ACTION_INVALID)
		action = rules->default_action;
	else
		action = pol->parsed->global_default_action;

	rcu_read_unlock();
eval:
	if (action == __IPE_ACTION_DENY)
		rc = -EACCES;

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

	if (mnt_sb == pinned_sb)
		pinned_sb = ERR_PTR(-EIO);

	spin_unlock(&pin_lock);
}
