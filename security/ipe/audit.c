// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include <linux/slab.h>
#include <linux/audit.h>
#include <linux/types.h>
#include <crypto/hash.h>

#include "ipe.h"
#include "eval.h"
#include "hooks.h"
#include "policy.h"
#include "audit.h"
#include "digest.h"

#define ACTSTR(x) ((x) == __IPE_ACTION_ALLOW ? "ALLOW" : "DENY")

#define IPE_AUDIT_HASH_ALG "sha256"

#define AUDIT_POLICY_LOAD_FMT "policy_name=\"%s\" policy_version=%hu.%hu.%hu "\
			      "policy_digest=" IPE_AUDIT_HASH_ALG ":"
#define AUDIT_OLD_ACTIVE_POLICY_FMT "old_active_pol_name=\"%s\" "\
				    "old_active_pol_version=%hu.%hu.%hu "\
				    "old_policy_digest=" IPE_AUDIT_HASH_ALG ":"
#define AUDIT_NEW_ACTIVE_POLICY_FMT "new_active_pol_name=\"%s\" "\
				    "new_active_pol_version=%hu.%hu.%hu "\
				    "new_policy_digest=" IPE_AUDIT_HASH_ALG ":"

static const char *const audit_op_names[__IPE_OP_MAX] = {
	"EXECUTE",
	"FIRMWARE",
	"KMODULE",
	"KEXEC_IMAGE",
	"KEXEC_INITRAMFS",
	"IMA_POLICY",
	"IMA_X509_CERT",
};

static const char *const audit_prop_names[__IPE_PROP_MAX] = {
	"boot_verified=FALSE",
	"boot_verified=TRUE",
#ifdef CONFIG_IPE_PROP_DM_VERITY
	"dmverity_roothash=",
	"dmverity_signature=FALSE",
	"dmverity_signature=TRUE",
#endif /* CONFIG_IPE_PROP_DM_VERITY */
};

#ifdef CONFIG_IPE_PROP_DM_VERITY
/**
 * audit_dmv_roothash - audit a roothash of a dmverity volume.
 * @ab: Supplies a pointer to the audit_buffer to append to.
 * @r: Supplies a pointer to the digest structure.
 */
static void audit_dmv_roothash(struct audit_buffer *ab, const void *rh)
{
	ipe_digest_audit(ab, rh);
}
#else
static void audit_dmv_roothash(struct audit_buffer *ab, const void *rh)
{
}
#endif /* CONFIG_IPE_PROP_DM_VERITY */

/**
 * audit_rule - audit an IPE policy rule approximation.
 * @ab: Supplies a pointer to the audit_buffer to append to.
 * @r: Supplies a pointer to the ipe_rule to approximate a string form for.
 */
static void audit_rule(struct audit_buffer *ab, const struct ipe_rule *r)
{
	const struct ipe_prop *ptr;

	audit_log_format(ab, "rule=\"op=%s ", audit_op_names[r->op]);

	list_for_each_entry(ptr, &r->props, next) {
		audit_log_format(ab, "%s", audit_prop_names[ptr->type]);
		if (ptr->type == __IPE_PROP_DMV_ROOTHASH)
			audit_dmv_roothash(ab, ptr->value);

		audit_log_format(ab, " ");
	}

	audit_log_format(ab, "action=%s\"", ACTSTR(r->action));
}

/**
 * ipe_audit_match - audit a match for IPE policy.
 * @ctx: Supplies a pointer to the evaluation context that was used in the
 *	 evaluation.
 * @match_type: Supplies the scope of the match: rule, operation default,
 *		global default.
 * @act: Supplies the IPE's evaluation decision, deny or allow.
 * @r: Supplies a pointer to the rule that was matched, if possible.
 * @enforce: Supplies the enforcement/permissive state at the point
 *	     the enforcement decision was made.
 */
void ipe_audit_match(const struct ipe_eval_ctx *const ctx,
		     enum ipe_match match_type,
		     enum ipe_action_type act, const struct ipe_rule *const r)
{
	struct inode *inode;
	struct audit_buffer *ab;
	const char *op = audit_op_names[ctx->op];

	if (act != __IPE_ACTION_DENY && !READ_ONCE(success_audit))
		return;

	ab = audit_log_start(audit_context(), GFP_KERNEL, AUDIT_IPE_ACCESS);
	if (!ab)
		return;

	if (ctx->file) {
		audit_log_d_path(ab, "path=", &ctx->file->f_path);
		inode = file_inode(ctx->file);
		if (inode) {
			audit_log_format(ab, " dev=");
			audit_log_untrustedstring(ab, inode->i_sb->s_id);
			audit_log_format(ab, " ino=%lu ", inode->i_ino);
		}
	}

	if (match_type == __IPE_MATCH_RULE)
		audit_rule(ab, r);
	else if (match_type == __IPE_MATCH_TABLE)
		audit_log_format(ab, "rule=\"DEFAULT op=%s action=%s\"", op,
				 ACTSTR(act));
	else
		audit_log_format(ab, "rule=\"DEFAULT action=%s\"",
				 ACTSTR(act));

	audit_log_end(ab);
}

/**
 * audit_policy - Audit a policy's name, version and thumbprint to @ab.
 * @ab: Supplies a pointer to the audit buffer to append to.
 * @p: Supplies a pointer to the policy to audit.
 */
static void audit_policy(struct audit_buffer *ab,
			 const char *audit_format,
			 const struct ipe_policy *const p)
{
	u8 *digest = NULL;
	struct crypto_shash *tfm;
	SHASH_DESC_ON_STACK(desc, tfm);

	tfm = crypto_alloc_shash(IPE_AUDIT_HASH_ALG, 0, 0);
	if (IS_ERR(tfm))
		return;

	desc->tfm = tfm;

	digest = kzalloc(crypto_shash_digestsize(tfm), GFP_KERNEL);
	if (!digest)
		goto out;

	if (crypto_shash_init(desc))
		goto out;

	if (crypto_shash_update(desc, p->pkcs7, p->pkcs7len))
		goto out;

	if (crypto_shash_final(desc, digest))
		goto out;

	audit_log_format(ab, audit_format, p->parsed->name,
			 p->parsed->version.major, p->parsed->version.minor,
			 p->parsed->version.rev);
	audit_log_n_hex(ab, digest, crypto_shash_digestsize(tfm));

out:
	kfree(digest);
	crypto_free_shash(tfm);
}

/**
 * ipe_audit_policy_activation - Audit a policy being made the active policy.
 * @p: Supplies a pointer to the policy to audit.
 */
void ipe_audit_policy_activation(const struct ipe_policy *const op,
				 const struct ipe_policy *const np)
{
	struct audit_buffer *ab;

	ab = audit_log_start(audit_context(), GFP_KERNEL,
			     AUDIT_IPE_CONFIG_CHANGE);
	if (!ab)
		return;

	audit_policy(ab, AUDIT_OLD_ACTIVE_POLICY_FMT, op);
	audit_log_format(ab, " ");
	audit_policy(ab, AUDIT_NEW_ACTIVE_POLICY_FMT, np);
	audit_log_format(ab, " auid=%u ses=%u lsm=ipe res=1",
			 from_kuid(&init_user_ns, audit_get_loginuid(current)),
			 audit_get_sessionid(current));

	audit_log_end(ab);
}

/**
 * ipe_audit_policy_load - Audit a policy being loaded into the kernel.
 * @p: Supplies a pointer to the policy to audit.
 */
void ipe_audit_policy_load(const struct ipe_policy *const p)
{
	struct audit_buffer *ab;

	ab = audit_log_start(audit_context(), GFP_KERNEL,
			     AUDIT_IPE_POLICY_LOAD);
	if (!ab)
		return;

	audit_policy(ab, AUDIT_POLICY_LOAD_FMT, p);
	audit_log_format(ab, " auid=%u ses=%u lsm=ipe res=1",
			 from_kuid(&init_user_ns, audit_get_loginuid(current)),
			 audit_get_sessionid(current));

	audit_log_end(ab);
}

/**
 * ipe_audit_enforce - Audit a change in IPE's enforcement state.
 * @new_enforce: The new value enforce to be set.
 * @old_enforce: The old value currently in enforce.
 */
void ipe_audit_enforce(bool new_enforce, bool old_enforce)
{
	struct audit_buffer *ab;

	ab = audit_log_start(audit_context(), GFP_KERNEL, AUDIT_MAC_STATUS);
	if (!ab)
		return;

	audit_log_format(ab, "enforcing=%d old_enforcing=%d auid=%u ses=%u"
			 " enabled=1 old-enabled=1 lsm=ipe res=1",
			 new_enforce, old_enforce,
			 from_kuid(&init_user_ns, audit_get_loginuid(current)),
			 audit_get_sessionid(current));

	audit_log_end(ab);
}
