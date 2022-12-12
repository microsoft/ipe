// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include <linux/types.h>
#include <linux/parser.h>

#include "policy.h"
#include "policy_parser.h"

#define START_COMMENT	'#'

/**
 * new_parsed_policy - Allocate and initialize a parsed policy.
 *
 * Return:
 * * !IS_ERR	- OK
 * * -ENOMEM	- Out of memory
 */
static struct ipe_parsed_policy *new_parsed_policy(void)
{
	size_t i = 0;
	struct ipe_parsed_policy *p = NULL;
	struct ipe_op_table *t = NULL;

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return ERR_PTR(-ENOMEM);

	p->global_default_action = __IPE_ACTION_INVALID;

	for (i = 0; i < ARRAY_SIZE(p->rules); ++i) {
		t = &p->rules[i];

		t->default_action = __IPE_ACTION_INVALID;
		INIT_LIST_HEAD(&t->rules);
	}

	return p;
}

/**
 * remove_comment - Truncate all chars following START_COMMENT in a string.
 *
 * @line: Supplies a poilcy line string for preprocessing.
 */
static void remove_comment(char *line)
{
	line = strchr(line, START_COMMENT);

	if (line)
		*line = '\0';
}

/**
 * remove_trailing_spaces - Truncate all trailing spaces in a string.
 *
 * @line: Supplies a poilcy line string for preprocessing.
 *
 * Return: The length of truncated string.
 */
static size_t remove_trailing_spaces(char *line)
{
	size_t i = 0;

	for (i = strlen(line); i > 0 && (line[i - 1] == ' ' || line[i - 1] == '\t'); --i)
		;

	line[i] = '\0';

	return i;
}

/**
 * parse_version - Parse policy version.
 * @ver: Supplies a version string to be parsed.
 * @p: Supplies the partial parsed policy.
 *
 * Return:
 * * 0	- OK
 * * !0	- Standard errno
 */
static int parse_version(char *ver, struct ipe_parsed_policy *p)
{
	int rc = 0;
	size_t sep_count = 0;
	char *token;
	u16 *const cv[] = { &p->version.major, &p->version.minor, &p->version.rev };

	while ((token = strsep(&ver, ".")) != NULL) {
		/* prevent overflow */
		if (sep_count >= ARRAY_SIZE(cv))
			return -EBADMSG;

		rc = kstrtou16(token, 10, cv[sep_count]);
		if (rc)
			return rc;

		++sep_count;
	}

	/* prevent underflow */
	if (sep_count != ARRAY_SIZE(cv))
		rc = -EBADMSG;

	return rc;
}

enum header_opt {
	__IPE_HEADER_POLICY_NAME = 0,
	__IPE_HEADER_POLICY_VERSION,
	__IPE_HEADER_MAX
};

static const match_table_t header_tokens = {
	{__IPE_HEADER_POLICY_NAME,	"policy_name=%s"},
	{__IPE_HEADER_POLICY_VERSION,	"policy_version=%s"},
	{__IPE_HEADER_MAX,		NULL}
};

/**
 * parse_header - Parse policy header information.
 * @line: Supplies header line to be parsed.
 * @p: Supplies the partial parsed policy.
 *
 * Return:
 * * 0	- OK
 * * !0	- Standard errno
 */
static int parse_header(char *line, struct ipe_parsed_policy *p)
{
	int rc = 0;
	char *t, *ver = NULL;
	substring_t args[MAX_OPT_ARGS];
	size_t idx = 0;

	while ((t = strsep(&line, " \t")) != NULL) {
		int token;

		if (*t == '\0')
			continue;
		if (idx >= __IPE_HEADER_MAX) {
			rc = -EBADMSG;
			goto err;
		}

		token = match_token(t, header_tokens, args);
		if (token != idx) {
			rc = -EBADMSG;
			goto err;
		}

		switch (token) {
		case __IPE_HEADER_POLICY_NAME:
			p->name = match_strdup(&args[0]);
			if (!p->name)
				rc = -ENOMEM;
			break;
		case __IPE_HEADER_POLICY_VERSION:
			ver = match_strdup(&args[0]);
			if (!ver) {
				rc = -ENOMEM;
				break;
			}
			rc = parse_version(ver, p);
			break;
		default:
			rc = -EBADMSG;
		}
		if (rc)
			goto err;
		++idx;
	}

	if (idx != __IPE_HEADER_MAX) {
		rc = -EBADMSG;
		goto err;
	}

out:
	kfree(ver);
	return rc;
err:
	kfree(p->name);
	p->name = NULL;
	goto out;
}

/**
 * token_default - Determine if the given token is "DEFAULT".
 * @token: Supplies the token string to be compared.
 *
 * Return:
 * * 0	- The token is not "DEFAULT"
 * * !0	- The token is "DEFAULT"
 */
static bool token_default(char *token)
{
	return !strcmp(token, "DEFAULT");
}

/**
 * free_rule - Free the supplied ipe_rule struct.
 * @r: Supplies the ipe_rule struct to be freed.
 *
 * Free a ipe_rule struct @r. Note @r must be removed from any lists before
 * calling this function.
 */
static void free_rule(struct ipe_rule *r)
{
	struct ipe_prop *p, *t;

	if (IS_ERR_OR_NULL(r))
		return;

	list_for_each_entry_safe(p, t, &r->props, next) {
		list_del(&p->next);
		kfree(p);
	}

	kfree(r);
}

static const match_table_t operation_tokens = {
	{__IPE_OP_EXEC,			"op=EXECUTE"},
	{__IPE_OP_FIRMWARE,		"op=FIRMWARE"},
	{__IPE_OP_KERNEL_MODULE,	"op=KMODULE"},
	{__IPE_OP_KEXEC_IMAGE,		"op=KEXEC_IMAGE"},
	{__IPE_OP_KEXEC_INITRAMFS,	"op=KEXEC_INITRAMFS"},
	{__IPE_OP_IMA_POLICY,		"op=IMA_POLICY"},
	{__IPE_OP_IMA_X509,		"op=IMA_X509_CERT"},
	{__IPE_OP_INVALID,		NULL}
};

/**
 * parse_operation - Parse the operation type given a token string.
 * @t: Supplies the token string to be parsed.
 *
 * Return: The parsed operation type.
 */
static enum ipe_op_type parse_operation(char *t)
{
	substring_t args[MAX_OPT_ARGS];

	return match_token(t, operation_tokens, args);
}

static const match_table_t action_tokens = {
	{__IPE_ACTION_ALLOW,	"action=ALLOW"},
	{__IPE_ACTION_DENY,	"action=DENY"},
	{__IPE_ACTION_INVALID,	NULL}
};

/**
 * parse_action - Parse the action type given a token string.
 * @t: Supplies the token string to be parsed.
 *
 * Return: The parsed action type.
 */
static enum ipe_action_type parse_action(char *t)
{
	substring_t args[MAX_OPT_ARGS];

	return match_token(t, action_tokens, args);
}

/**
 * parse_property - Parse the property type given a token string.
 * @t: Supplies the token string to be parsed.
 * @r: Supplies the ipe_rule the parsed property will be associated with.
 *
 * Return:
 * * !IS_ERR	- OK
 * * -ENOMEM	- Out of memory
 * * -EBADMSG	- The supplied token cannot be parsed
 */
static int parse_property(char *t, struct ipe_rule *r)
{
	return -EBADMSG;
}

/**
 * parse_rule - parse a policy rule line.
 * @line: Supplies rule line to be parsed.
 * @p: Supplies the partial parsed policy.
 *
 * Return:
 * * !IS_ERR	- OK
 * * -ENOMEM	- Out of memory
 * * -EBADMSG	- Policy syntax error
 */
static int parse_rule(char *line, struct ipe_parsed_policy *p)
{
	int rc = 0;
	bool first_token = true, is_default_rule = false;
	bool op_parsed = false;
	enum ipe_op_type op = __IPE_OP_INVALID;
	enum ipe_action_type action = __IPE_ACTION_INVALID;
	struct ipe_rule *r = NULL;
	char *t;

	r = kzalloc(sizeof(*r), GFP_KERNEL);
	if (!r)
		return -ENOMEM;

	INIT_LIST_HEAD(&r->next);
	INIT_LIST_HEAD(&r->props);

	while (t = strsep(&line, " \t"), line) {
		if (*t == '\0')
			continue;
		if (first_token && token_default(t)) {
			is_default_rule = true;
		} else {
			if (!op_parsed) {
				op = parse_operation(t);
				if (op == __IPE_OP_INVALID)
					rc = -EBADMSG;
				else
					op_parsed = true;
			} else {
				rc = parse_property(t, r);
			}
		}

		if (rc)
			goto err;
		first_token = false;
	}

	action = parse_action(t);
	if (action == __IPE_ACTION_INVALID) {
		rc = -EBADMSG;
		goto err;
	}

	if (is_default_rule) {
		if (!list_empty(&r->props)) {
			rc = -EBADMSG;
		} else if (op == __IPE_OP_INVALID) {
			if (p->global_default_action != __IPE_ACTION_INVALID)
				rc = -EBADMSG;
			else
				p->global_default_action = action;
		} else {
			if (p->rules[op].default_action != __IPE_ACTION_INVALID)
				rc = -EBADMSG;
			else
				p->rules[op].default_action = action;
		}
	} else if (op != __IPE_OP_INVALID && action != __IPE_ACTION_INVALID) {
		r->op = op;
		r->action = action;
	} else {
		rc = -EBADMSG;
	}

	if (rc)
		goto err;
	if (!is_default_rule)
		list_add_tail(&r->next, &p->rules[op].rules);
	else
		free_rule(r);

out:
	return rc;
err:
	free_rule(r);
	goto out;
}

/**
 * free_parsed_policy - free a parsed policy structure.
 * @p: Supplies the parsed policy.
 */
void free_parsed_policy(struct ipe_parsed_policy *p)
{
	size_t i = 0;
	struct ipe_rule *pp, *t;

	if (IS_ERR_OR_NULL(p))
		return;

	for (i = 0; i < ARRAY_SIZE(p->rules); ++i)
		list_for_each_entry_safe(pp, t, &p->rules[i].rules, next) {
			list_del(&pp->next);
			free_rule(pp);
		}

	kfree(p->name);
	kfree(p);
}

/**
 * validate_policy - validate a parsed policy.
 * @p: Supplies the fully parsed policy.
 *
 * Given a policy structure that was just parsed, validate that all
 * necessary fields are present, initialized correctly.
 *
 * A parsed policy can be in an invalid state for use (a default was
 * undefined) by just parsing the policy.
 *
 * Return:
 * * 0		- OK
 * * -EBADMSG	- Policy is invalid
 */
static int validate_policy(const struct ipe_parsed_policy *p)
{
	int i = 0;

	if (p->global_default_action != __IPE_ACTION_INVALID)
		return 0;

	for (i = 0; i < ARRAY_SIZE(p->rules); ++i) {
		if (p->rules[i].default_action == __IPE_ACTION_INVALID)
			return -EBADMSG;
	}

	return 0;
}

/**
 * parse_policy - Given a string, parse the string into an IPE policy.
 * @p: partially filled ipe_policy structure to populate with the result.
 *     it must have text and textlen set.
 *
 * Return:
 * * 0		- OK
 * * -EBADMSG	- Policy is invalid
 * * -ENOMEM	- Out of Memory
 */
int parse_policy(struct ipe_policy *p)
{
	int rc = 0;
	size_t len;
	char *policy = NULL, *dup = NULL;
	char *line = NULL;
	bool header_parsed = false;
	struct ipe_parsed_policy *pp = NULL;

	if (!p->textlen)
		return -EBADMSG;

	policy = kmemdup_nul(p->text, p->textlen, GFP_KERNEL);
	if (!policy)
		return -ENOMEM;
	dup = policy;

	pp = new_parsed_policy();
	if (IS_ERR(pp)) {
		rc = PTR_ERR(pp);
		goto out;
	}

	while ((line = strsep(&policy, "\n\r")) != NULL) {
		remove_comment(line);
		len = remove_trailing_spaces(line);
		if (!len)
			continue;

		if (!header_parsed) {
			rc = parse_header(line, pp);
			if (rc)
				goto err;
			header_parsed = true;
		} else {
			rc = parse_rule(line, pp);
			if (rc)
				goto err;
		}
	}

	if (!header_parsed || validate_policy(pp)) {
		rc = -EBADMSG;
		goto err;
	}

	p->parsed = pp;

out:
	kfree(dup);
	return rc;
err:
	free_parsed_policy(pp);
	goto out;
}
