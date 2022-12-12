/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_DM_VERITY_H
#define _LINUX_DM_VERITY_H

struct dm_verity_digest {
	const char *alg;
	const u8 *digest;
	size_t digest_len;
};

#endif /* _LINUX_DM_VERITY_H */
