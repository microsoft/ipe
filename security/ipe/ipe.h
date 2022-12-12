/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#ifndef _IPE_H
#define _IPE_H

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) "IPE: " fmt

#include <linux/lsm_hooks.h>

extern bool ipe_enabled;

#endif /* _IPE_H */
