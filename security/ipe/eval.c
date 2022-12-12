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
#include <linux/moduleparam.h>

#include "ipe.h"
#include "eval.h"
#include "hooks.h"
#include "policy.h"
#include "audit.h"
#include "digest.h"

struct ipe_policy __rcu *ipe_active_policy;
bool success_audit;
bool enforce = true;
#define INO_BLOCK_DEV(ino) ((ino)->i_sb->s_bdev)

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

#ifdef CONFIG_IPE_PROP_DM_VERITY
/**
 * build_ipe_bdev_ctx - Build ipe_bdev field of an evaluation context.
 * @ctx: Supplies a pointer to the context to be populdated.
 * @ino: Supplies the inode struct of the file triggered IPE event.
 */
static void build_ipe_bdev_ctx(struct ipe_eval_ctx *ctx, const struct inode *const ino)
{
	if (INO_BLOCK_DEV(ino))
		ctx->ipe_bdev = ipe_bdev(INO_BLOCK_DEV(ino));
}
#else
static void build_ipe_bdev_ctx(struct ipe_eval_ctx *ctx, const struct inode *const ino)
{
}
#endif /* CONFIG_IPE_PROP_DM_VERITY */

#ifdef CONFIG_IPE_PROP_FS_VERITY
/**
 * build_ipe_inode_ctx - Build inode fields of an evaluation context.
 * @ctx: Supplies a pointer to the context to be populdated.
 * @ino: Supplies the inode struct of the file triggered IPE event.
 */
static void build_ipe_inode_ctx(struct ipe_eval_ctx *ctx, const struct inode *const ino)
{
	ctx->ino = ino;
	ctx->ipe_inode = ipe_inode(ctx->ino);
}
#else
static void build_ipe_inode_ctx(struct ipe_eval_ctx *ctx, const struct inode *const ino)
{
}
#endif /* CONFIG_IPE_PROP_FS_VERITY */

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

	if (op == __IPE_OP_EXEC && file)
		pin_sb(FILE_SUPERBLOCK(file));

	ctx->file = file;
	ctx->op = op;

	if (file) {
		ctx->from_init_sb = from_pinned(FILE_SUPERBLOCK(file));
		ino = d_real_inode(file->f_path.dentry);
		build_ipe_bdev_ctx(ctx, ino);
		build_ipe_inode_ctx(ctx, ino);
	}
}

#ifdef CONFIG_IPE_PROP_DM_VERITY
/**
 * evaluate_dmv_roothash - Evaluate @ctx against a dmv roothash property.
 * @ctx: Supplies a pointer to the context being evaluated.
 * @p: Supplies a pointer to the property being evaluated.
 *
 * Return:
 * * true	- The current @ctx match the @p
 * * false	- The current @ctx doesn't match the @p
 */
static bool evaluate_dmv_roothash(const struct ipe_eval_ctx *const ctx,
				  struct ipe_prop *p)
{
	return !!ctx->ipe_bdev &&
	       ipe_digest_eval(p->value,
			       ctx->ipe_bdev->digest,
			       ctx->ipe_bdev->digest_len,
			       ctx->ipe_bdev->digest_algo);
}

/**
 * evaluate_dmv_sig_false: Analyze @ctx against a dmv sig false property.
 * @ctx: Supplies a pointer to the context being evaluated.
 * @p: Supplies a pointer to the property being evaluated.
 *
 * Return:
 * * true	- The current @ctx match the @p
 * * false	- The current @ctx doesn't match the @p
 */
static bool evaluate_dmv_sig_false(const struct ipe_eval_ctx *const ctx,
				   struct ipe_prop *p)
{
	return !ctx->ipe_bdev || (!ctx->ipe_bdev->dm_verity_signed);
}

/**
 * evaluate_dmv_sig_true: Analyze @ctx against a dmv sig true property.
 * @ctx: Supplies a pointer to the context being evaluated.
 * @p: Supplies a pointer to the property being evaluated.
 *
 * Return:
 * * true	- The current @ctx match the @p
 * * false	- The current @ctx doesn't match the @p
 */
static bool evaluate_dmv_sig_true(const struct ipe_eval_ctx *const ctx,
				  struct ipe_prop *p)
{
	return ctx->ipe_bdev && (!!ctx->ipe_bdev->dm_verity_signed);
}
#else
static bool evaluate_dmv_roothash(const struct ipe_eval_ctx *const ctx,
				  struct ipe_prop *p)
{
	return false;
}

static bool evaluate_dmv_sig_false(const struct ipe_eval_ctx *const ctx,
				   struct ipe_prop *p)
{
	return false;
}

static bool evaluate_dmv_sig_true(const struct ipe_eval_ctx *const ctx,
				  struct ipe_prop *p)
{
	return false;
}
#endif /* CONFIG_IPE_PROP_DM_VERITY */

#ifdef CONFIG_IPE_PROP_FS_VERITY
/**
 * evaluate_fsv_digest - Analyze @ctx against a fsv digest property.
 * @ctx: Supplies a pointer to the context being evaluated.
 * @p: Supplies a pointer to the property being evaluated.
 *
 * Return:
 * * true	- The current @ctx match the @p
 * * false	- The current @ctx doesn't match the @p
 */
static bool evaluate_fsv_digest(const struct ipe_eval_ctx *const ctx,
				struct ipe_prop *p)
{
	enum hash_algo alg;
	u8 digest[FS_VERITY_MAX_DIGEST_SIZE];

	if (!ctx->ino)
		return false;
	if (!fsverity_get_digest((struct inode *)ctx->ino,
				 digest,
				 NULL,
				 &alg)) {
		return false;
	}

	return ipe_digest_eval(p->value,
			       digest,
			       hash_digest_size[alg],
			       hash_algo_name[alg]);
}

/**
 * evaluate_fsv_sig_false - Analyze @ctx against a fsv sig false property.
 * @ctx: Supplies a pointer to the context being evaluated.
 * @p: Supplies a pointer to the property being evaluated.
 *
 * Return:
 * * true	- The current @ctx match the @p
 * * false	- The current @ctx doesn't match the @p
 */
static bool evaluate_fsv_sig_false(const struct ipe_eval_ctx *const ctx,
				   struct ipe_prop *p)
{
	return !ctx->ino ||
	       !IS_VERITY(ctx->ino) ||
	       !ctx->ipe_inode ||
	       !ctx->ipe_inode->fs_verity_signed;
}

/**
 * evaluate_fsv_sig_true - Analyze @ctx against a fsv sig true property.
 * @ctx: Supplies a pointer to the context being evaluated.
 * @p: Supplies a pointer to the property being evaluated.
 *
 * Return:
 * * true - The current @ctx match the @p
 * * false - The current @ctx doesn't match the @p
 */
static bool evaluate_fsv_sig_true(const struct ipe_eval_ctx *const ctx,
				  struct ipe_prop *p)
{
	return ctx->ino &&
	       IS_VERITY(ctx->ino) &&
	       ctx->ipe_inode &&
	       ctx->ipe_inode->fs_verity_signed;
}
#else
static bool evaluate_fsv_digest(const struct ipe_eval_ctx *const ctx,
				struct ipe_prop *p)
{
	return false;
}

static bool evaluate_fsv_sig_false(const struct ipe_eval_ctx *const ctx,
				   struct ipe_prop *p)
{
	return false;
}

static bool evaluate_fsv_sig_true(const struct ipe_eval_ctx *const ctx,
				  struct ipe_prop *p)
{
	return false;
}
#endif /* CONFIG_IPE_PROP_FS_VERITY */

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
	case __IPE_PROP_DMV_ROOTHASH:
		return evaluate_dmv_roothash(ctx, p);
	case __IPE_PROP_DMV_SIG_FALSE:
		return evaluate_dmv_sig_false(ctx, p);
	case __IPE_PROP_DMV_SIG_TRUE:
		return evaluate_dmv_sig_true(ctx, p);
	case __IPE_PROP_FSV_DIGEST:
		return evaluate_fsv_digest(ctx, p);
	case __IPE_PROP_FSV_SIG_FALSE:
		return evaluate_fsv_sig_false(ctx, p);
	case __IPE_PROP_FSV_SIG_TRUE:
		return evaluate_fsv_sig_true(ctx, p);
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
	bool enforcing = true;
	enum ipe_action_type action;
	enum ipe_match match_type;
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

	enforcing = READ_ONCE(enforce);

	if (ctx->op == __IPE_OP_INVALID) {
		action = pol->parsed->global_default_action;
		match_type = __IPE_MATCH_GLOBAL;
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

	if (match) {
		action = rule->action;
		match_type = __IPE_MATCH_RULE;
	} else if (rules->default_action != __IPE_ACTION_INVALID) {
		action = rules->default_action;
		match_type = __IPE_MATCH_TABLE;
	} else {
		action = pol->parsed->global_default_action;
		match_type = __IPE_MATCH_GLOBAL;
	}

	rcu_read_unlock();
eval:
	ipe_audit_match(ctx, match_type, action, rule);

	if (action == __IPE_ACTION_DENY)
		rc = -EACCES;

	if (!enforcing)
		rc = 0;

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

/* Set the right module name */
#ifdef KBUILD_MODNAME
#undef KBUILD_MODNAME
#define KBUILD_MODNAME "ipe"
#endif

module_param(success_audit, bool, 0400);
MODULE_PARM_DESC(success_audit, "Start IPE with success auditing enabled");
module_param(enforce, bool, 0400);
MODULE_PARM_DESC(enforce, "Start IPE in enforce or permissive mode");
