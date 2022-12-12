/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#ifndef _IPE_DIGEST_H
#define _IPE_DIGEST_H

#include "policy.h"
#include <linux/types.h>
#include <linux/audit.h>

struct digest_info {
	const char *alg;
	const char *raw_digest;
	const u8 *digest;
	size_t digest_len;
};

int ipe_digest_parse(const char *valstr, void **value);
void ipe_digest_free(void **value);
void ipe_digest_audit(struct audit_buffer *ab, const void *val);
bool ipe_digest_eval(const void *expect, const u8 *digest, size_t digest_len,
		     const char *alg);

#endif /* _IPE_DIGEST_H */
