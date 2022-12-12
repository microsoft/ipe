/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_DM_VERITY_H
#define _LINUX_DM_VERITY_H

#include <linux/types.h>
#include <crypto/hash_info.h>
#include <linux/device-mapper.h>

struct dm_verity_digest {
	const char *alg;
	const u8 *digest;
	size_t digest_len;
};

#define DM_VERITY_SIGNATURE_SEC_NAME DM_NAME	".verity-signature"
#define DM_VERITY_ROOTHASH_SEC_NAME  DM_NAME	".verity-roothash"

#endif /* _LINUX_DM_VERITY_H */
