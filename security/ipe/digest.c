// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include "digest.h"

/**
 * ipe_digest_parse - parse a digest in IPE's policy.
 * @valstr: Supplies the string parsed from the policy.
 * @value: Supplies a pointer to be populated with the result.
 *
 * Digests in IPE are defined in a standard way:
 *	<alg_name>:<hex>
 *
 * Use this function to create a property to parse the digest
 * consistently. The parsed digest will be saved in @value in IPE's
 * policy.
 *
 * Return:
 * * 0	- OK
 * * !0	- Error
 */
int ipe_digest_parse(const char *valstr, void **value)
{
	char *sep, *raw_digest;
	size_t raw_digest_len;
	int rc = 0;
	u8 *digest = NULL;
	struct digest_info *info = NULL;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	sep = strchr(valstr, ':');
	if (!sep) {
		rc = -EBADMSG;
		goto err;
	}

	info->alg = kstrndup(valstr, sep - valstr, GFP_KERNEL);
	if (!info->alg) {
		rc = -ENOMEM;
		goto err;
	}

	raw_digest = sep + 1;
	raw_digest_len = strlen(raw_digest);
	info->raw_digest = kstrndup(raw_digest, raw_digest_len, GFP_KERNEL);
	if (!info->raw_digest) {
		rc = -ENOMEM;
		goto err_free_alg;
	}

	info->digest_len = (raw_digest_len + 1) / 2;
	digest = kzalloc(info->digest_len, GFP_KERNEL);
	if (!digest) {
		rc = -ENOMEM;
		goto err_free_raw;
	}

	rc = hex2bin(digest, raw_digest, info->digest_len);
	if (rc < 0) {
		rc = -EINVAL;
		goto err_free_raw;
	}

	info->digest = digest;
	*value = info;
	return 0;

err_free_raw:
	kfree(info->raw_digest);
err_free_alg:
	kfree(info->alg);
err:
	kfree(digest);
	kfree(info);
	return rc;
}

/**
 * ipe_digest_eval - evaluate an IPE digest against another digest.
 * @expect: Supplies the policy-provided digest value.
 * @digest: Supplies the digest to compare against the policy digest value.
 * @digest_len: The length of @digest.
 * @alg: Supplies the name of the algorithm used to calculated @digest.
 *
 * Return:
 * * true	- digests match
 * * false	- digests do not match
 */
bool ipe_digest_eval(const void *expect, const u8 *digest, size_t digest_len,
		     const char *alg)
{
	const struct digest_info *info = (struct digest_info *)expect;

	return (digest_len == info->digest_len) && !strcmp(alg, info->alg) &&
	       (!memcmp(info->digest, digest, info->digest_len));
}

/**
 * ipe_digest_free - free an IPE digest.
 * @value: Supplies a pointer the policy-provided digest value to free.
 */
void ipe_digest_free(void **value)
{
	struct digest_info *info = (struct digest_info *)(*value);

	if (IS_ERR_OR_NULL(info))
		return;

	kfree(info->alg);
	kfree(info->raw_digest);
	kfree(info->digest);
	kfree(info);
}

/**
 * ipe_digest_audit - audit a digest that was sourced from IPE's policy.
 * @ab: Supplies the audit_buffer to append the formatted result.
 * @val: Supplies a pointer to source the audit record from.
 *
 * Digests in IPE are defined in a standard way:
 *	<alg_name>:<hex>
 *
 * Use this function to create a property to audit the digest
 * consistently.
 *
 * Return:
 * 0 - OK
 * !0 - Error
 */
void ipe_digest_audit(struct audit_buffer *ab, const void *val)
{
	const struct digest_info *info = (struct digest_info *)val;

	audit_log_untrustedstring(ab, info->alg);
	audit_log_format(ab, ":");
	audit_log_untrustedstring(ab, info->raw_digest);
}
