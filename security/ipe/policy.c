// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include <linux/errno.h>
#include <linux/verification.h>

#include "ipe.h"
#include "eval.h"
#include "fs.h"
#include "policy.h"
#include "policy_parser.h"
#include "digest.h"

/* lock for synchronizing writers across ipe policy */
DEFINE_SPINLOCK(ipe_policy_lock);

/**
 * ver_to_u64 - Convert an internal ipe_policy_version to a u64.
 * @p: Policy to extract the version from.
 *
 * Bits (LSB is index 0):
 *	[48,32] -> Major
 *	[32,16] -> Minor
 *	[16, 0] -> Revision
 *
 * Return: u64 version of the embedded version structure.
 */
static inline u64 ver_to_u64(const struct ipe_policy *const p)
{
	u64 r = 0;

	r = (((u64)p->parsed->version.major) << 32)
	  | (((u64)p->parsed->version.minor) << 16)
	  | ((u64)(p->parsed->version.rev));

	return r;
}

/**
 * ipe_free_policy - Deallocate a given IPE policy.
 * @p: Supplies the policy to free.
 *
 * Safe to call on IS_ERR/NULL.
 */
void ipe_free_policy(struct ipe_policy *p)
{
	if (IS_ERR_OR_NULL(p))
		return;

	ipe_del_policyfs_node(p);
	free_parsed_policy(p->parsed);
	if (!p->pkcs7)
		kfree(p->text);
	kfree(p->pkcs7);
	kfree(p);
}

static int set_pkcs7_data(void *ctx, const void *data, size_t len,
			  size_t asn1hdrlen)
{
	struct ipe_policy *p = ctx;

	p->text = (const char *)data;
	p->textlen = len;

	return 0;
}

/**
 * ipe_update_policy - parse a new policy and replace @old with it.
 * @addr: Supplies a pointer to the i_private for saving policy.
 * @text: Supplies a pointer to the plain text policy.
 * @textlen: Supplies the length of @text.
 * @pkcs7: Supplies a pointer to a buffer containing a pkcs7 message.
 * @pkcs7len: Supplies the length of @pkcs7len.
 *
 * @text/@textlen is mutually exclusive with @pkcs7/@pkcs7len - see
 * ipe_new_policy.
 *
 * Return:
 * * !IS_ERR	- OK
 * * -ENOENT	- Policy doesn't exist
 * * -EINVAL	- New policy is invalid
 */
struct ipe_policy *ipe_update_policy(struct ipe_policy __rcu **addr,
				     const char *text, size_t textlen,
				     const char *pkcs7, size_t pkcs7len)
{
	int rc = 0;
	struct ipe_policy *old, *new = NULL;

	old = ipe_get_policy_rcu(*addr);
	if (!old) {
		rc = -ENOENT;
		goto err;
	}

	new = ipe_new_policy(text, textlen, pkcs7, pkcs7len);
	if (IS_ERR(new)) {
		rc = PTR_ERR(new);
		goto err;
	}

	if (strcmp(new->parsed->name, old->parsed->name)) {
		rc = -EINVAL;
		goto err;
	}

	if (ver_to_u64(old) > ver_to_u64(new)) {
		rc = -EINVAL;
		goto err;
	}

	if (ipe_is_policy_active(old)) {
		spin_lock(&ipe_policy_lock);
		rcu_assign_pointer(ipe_active_policy, new);
		spin_unlock(&ipe_policy_lock);
		synchronize_rcu();
	}

	rcu_assign_pointer(*addr, new);

	swap(new->policyfs, old->policyfs);
	ipe_free_policy(old);

out:
	return (rc < 0) ? ERR_PTR(rc) : new;
err:
	ipe_free_policy(new);
	goto out;
}

/**
 * ipe_new_policy - Allocate and parse an ipe_policy structure.
 *
 * @text: Supplies a pointer to the plain-text policy to parse.
 * @textlen: Supplies the length of @text.
 * @pkcs7: Supplies a pointer to a pkcs7-signed IPE policy.
 * @pkcs7len: Supplies the length of @pkcs7.
 *
 * @text/@textlen Should be NULL/0 if @pkcs7/@pkcs7len is set.
 *
 * The result will still need to be associated with a context via
 * ipe_add_policy.
 *
 * Return:
 * * !IS_ERR	- Success
 * * -EBADMSG	- Policy is invalid
 * * -ENOMEM	- Out of memory
 */
struct ipe_policy *ipe_new_policy(const char *text, size_t textlen,
				  const char *pkcs7, size_t pkcs7len)
{
	int rc = 0;
	struct ipe_policy *new = NULL;

	new = kzalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		return ERR_PTR(-ENOMEM);

	if (!text) {
		new->pkcs7len = pkcs7len;
		new->pkcs7 = kmemdup(pkcs7, pkcs7len, GFP_KERNEL);
		if (!new->pkcs7) {
			rc = -ENOMEM;
			goto err;
		}

		rc = verify_pkcs7_signature(NULL, 0, new->pkcs7, pkcs7len, NULL,
					    VERIFYING_UNSPECIFIED_SIGNATURE,
					    set_pkcs7_data, new);
		if (rc)
			goto err;
	} else {
		new->textlen = textlen;
		new->text = kstrdup(text, GFP_KERNEL);
		if (!new->text) {
			rc = -ENOMEM;
			goto err;
		}
	}

	rc = parse_policy(new);
	if (rc)
		goto err;

	return new;
err:
	ipe_free_policy(new);
	return ERR_PTR(rc);
}

/**
 * ipe_get_policy_rcu - Dereference a rcu-protected policy pointer.
 *
 * @p: rcu-protected pointer to a policy.
 *
 * Not safe to call on IS_ERR.
 *
 * Return: the value of @p
 */
struct ipe_policy *ipe_get_policy_rcu(struct ipe_policy __rcu *p)
{
	struct ipe_policy *rv = NULL;

	rcu_read_lock();
	rv = rcu_dereference(p);
	rcu_read_unlock();

	return rv;
}

/**
 * ipe_set_active_pol - Make @p the active policy.
 * @p: Supplies a pointer to the policy to make active.
 */
int ipe_set_active_pol(const struct ipe_policy *p)
{
	int rc = 0;
	struct ipe_policy *ap = NULL;

	ap = ipe_get_policy_rcu(ipe_active_policy);
	if (ap && ver_to_u64(ap) > ver_to_u64(p)) {
		rc = -EINVAL;
		goto out;
	}

	spin_lock(&ipe_policy_lock);
	rcu_assign_pointer(ipe_active_policy, p);
	spin_unlock(&ipe_policy_lock);
	synchronize_rcu();

out:
	return rc;
}

/**
 * ipe_is_policy_active - Determine whether @p is the active policy.
 * @p: Supplies a pointer to the policy to check.
 *
 * Return:
 * * true	- @p is the active policy
 * * false	- @p is not the active policy
 */
bool ipe_is_policy_active(const struct ipe_policy *p)
{
	bool rv;

	rcu_read_lock();
	rv = rcu_access_pointer(ipe_active_policy) == p;
	rcu_read_unlock();

	return rv;
}
