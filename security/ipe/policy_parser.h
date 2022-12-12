/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#ifndef _IPE_POLICY_PARSER_H
#define _IPE_POLICY_PARSER_H

int parse_policy(struct ipe_policy *p);
void free_parsed_policy(struct ipe_parsed_policy *p);

#endif /* _IPE_POLICY_PARSER_H */
