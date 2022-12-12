// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#include "ipe.h"
#include "policy.h"
#include "fs.h"

#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/types.h>
#include <linux/dcache.h>
#include <linux/security.h>

#define MAX_VERSION_SIZE ARRAY_SIZE("65535.65535.65535")

/**
 * find_policy - return a policy pointer saved in i_private of a dentry.
 * @f: Securityfs object that contains a link to the dentry containing the
 *     policy structure.
 *
 * Return: Always-Valid Address Pointer
 */
static inline struct ipe_policy __rcu **find_policy(struct file *f)
{
	struct dentry *link;

	link = d_inode(f->f_path.dentry)->i_private;

	return (struct ipe_policy __rcu **)&(d_inode(link)->i_private);
}

/**
 * ipefs_file - defines a file in securityfs.
 */
struct ipefs_file {
	const char *name;
	umode_t access;
	const struct file_operations *fops;
};

/**
 * read_pkcs7 - Read handler for "ipe/policies/$name/pkcs7".
 * @f: Supplies a file structure representing the securityfs node.
 * @data: Suppleis a buffer passed to the write syscall.
 * @len: Supplies the length of @data.
 * @offset: unused.
 *
 * @data will be populated with the pkcs7 blob representing the policy
 * on success. If the policy is unsigned (like the boot policy), this
 * will return -ENOENT.
 *
 * Return:
 * * >0	- Success, Length of buffer written
 * * <0	- Error
 */
static ssize_t read_pkcs7(struct file *f, char __user *data,
			  size_t len, loff_t *offset)
{
	int rc = 0;
	struct ipe_policy *p = NULL;

	p = ipe_get_policy_rcu(*find_policy(f));
	if (!p)
		return -ENOENT;

	if (!p->pkcs7) {
		rc = -ENOENT;
		goto out;
	}

	rc = simple_read_from_buffer(data, len, offset, p->pkcs7, p->pkcs7len);

out:
	return rc;
}

/**
 * read_policy - Read handler for "ipe/policies/$name/policy".
 * @f: Supplies a file structure representing the securityfs node.
 * @data: Suppleis a buffer passed to the write syscall.
 * @len: Supplies the length of @data.
 * @offset: unused.
 *
 * @data will be populated with the plain-text version of the policy
 * on success.
 *
 * Return:
 * * >0	- Success, Length of buffer written
 * * <0	- Error
 */
static ssize_t read_policy(struct file *f, char __user *data,
			   size_t len, loff_t *offset)
{
	int rc = 0;
	struct ipe_policy *p = NULL;

	p = ipe_get_policy_rcu(*find_policy(f));
	if (!p)
		return -ENOENT;

	rc = simple_read_from_buffer(data, len, offset, p->text, p->textlen);

	return rc;
}

/**
 * read_name: Read handler for "ipe/policies/$name/name".
 * @f: Supplies a file structure representing the securityfs node.
 * @data: Suppleis a buffer passed to the write syscall.
 * @len: Supplies the length of @data.
 * @offset: unused.
 *
 * @data will be populated with the policy_name attribute on success.
 *
 * Return:
 * * >0	- Success, Length of buffer written
 * * <0	- Error
 */
static ssize_t read_name(struct file *f, char __user *data,
			 size_t len, loff_t *offset)
{
	int rc = 0;
	struct ipe_policy *p = NULL;

	p = ipe_get_policy_rcu(*find_policy(f));
	if (!p)
		return -ENOENT;

	rc = simple_read_from_buffer(data, len, offset, p->parsed->name,
				     strlen(p->parsed->name));

	return rc;
}

/**
 * read_version - Read handler for "ipe/policies/$name/version".
 * @f: Supplies a file structure representing the securityfs node.
 * @data: Suppleis a buffer passed to the write syscall.
 * @len: Supplies the length of @data.
 * @offset: unused.
 *
 * @data will be populated with the version string on success.
 *
 * Return:
 * * >0	- Success, Length of buffer written
 * * <0	- Error
 */
static ssize_t read_version(struct file *f, char __user *data,
			    size_t len, loff_t *offset)
{
	ssize_t rc = 0;
	size_t bufsize = 0;
	struct ipe_policy *p = NULL;
	char buffer[MAX_VERSION_SIZE] = { 0 };

	p = ipe_get_policy_rcu(*find_policy(f));
	if (!p)
		return -ENOENT;

	bufsize = scnprintf(buffer, ARRAY_SIZE(buffer), "%hu.%hu.%hu",
			    p->parsed->version.major, p->parsed->version.minor,
			    p->parsed->version.rev);

	rc = simple_read_from_buffer(data, len, offset, buffer, bufsize);

	return rc;
}

/**
 * setactive - Write handler for "ipe/policies/$name/active".
 * @f: Supplies a file structure representing the securityfs node.
 * @data: Supplies a buffer passed to the write syscall.
 * @len: Supplies the length of @data.
 * @offset: unused.
 *
 * Return:
 * * >0	- Success, Length of buffer written
 * * <0	- Error
 */
static ssize_t setactive(struct file *f, const char __user *data,
			 size_t len, loff_t *offset)
{
	int rc = 0;
	bool value = false;
	struct ipe_policy *p = NULL;

	if (!file_ns_capable(f, &init_user_ns, CAP_MAC_ADMIN))
		return -EPERM;

	rc = kstrtobool_from_user(data, len, &value);
	if (rc)
		goto out;

	if (!value) {
		rc = -EINVAL;
		goto out;
	}

	p = ipe_get_policy_rcu(*find_policy(f));
	if (!p) {
		rc = -ENOENT;
		goto out;
	}

	rc = ipe_set_active_pol(p);

out:
	return (rc < 0) ? rc : len;
}

/**
 * getactive - Read handler for "ipe/policies/$name/active".
 * @f: Supplies a file structure representing the securityfs node.
 * @data: Suppleis a buffer passed to the write syscall.
 * @len: Supplies the length of @data.
 * @offset: unused.
 *
 * @data will be populated with the 1 or 0 depending on if the
 * corresponding policy is active.
 *
 * Return:
 * * >0	- Success, Length of buffer written
 * * <0	- Error
 */
static ssize_t getactive(struct file *f, char __user *data,
			 size_t len, loff_t *offset)
{
	int rc = 0;
	const char *str;
	struct ipe_policy *p = NULL;

	p = ipe_get_policy_rcu(*find_policy(f));
	if (!p) {
		rc = -ENOENT;
		goto out;
	}

	str = ipe_is_policy_active(p) ? "1" : "0";
	rc = simple_read_from_buffer(data, len, offset, str, 1);

out:
	return rc;
}

/**
 * update_policy - Write handler for "ipe/policies/$name/update".
 * @f: Supplies a file structure representing the securityfs node.
 * @data: Supplies a buffer passed to the write syscall.
 * @len: Supplies the length of @data.
 * @offset: unused.
 *
 * On success this updates the policy represented by $name,
 * in-place.
 *
 * Return:
 * * >0	- Success, Length of buffer written
 * * <0	- Error
 */
static ssize_t update_policy(struct file *f, const char __user *data,
			     size_t len, loff_t *offset)
{
	int rc = 0;
	char *copy = NULL;
	struct inode *ino = NULL;
	struct ipe_policy *new = NULL;
	struct ipe_policy __rcu **addr = NULL;

	if (!file_ns_capable(f, &init_user_ns, CAP_MAC_ADMIN))
		return -EPERM;

	copy = memdup_user(data, len);
	if (IS_ERR(copy)) {
		rc = PTR_ERR(copy);
		return rc;
	}

	ino = d_inode(f->f_path.dentry->d_parent);
	inode_lock(ino);
	addr = find_policy(f);
	new = ipe_update_policy(addr, NULL, 0, copy, len);
	inode_unlock(ino);
	synchronize_rcu();
	if (IS_ERR(new)) {
		rc = PTR_ERR(new);
		goto err;
	}

	kfree(copy);
	return len;
err:
	kfree(copy);
	return rc;
}

/**
 * delete_policy - write handler for  "ipe/policies/$name/delete".
 * @f: Supplies a file structure representing the securityfs node.
 * @data: Supplies a buffer passed to the write syscall.
 * @len: Supplies the length of @data.
 * @offset: unused.
 *
 * On success this deletes the policy represented by $name.
 *
 * Return:
 * * >0	- Success, Length of buffer written
 * * <0	- Error
 */
static ssize_t delete_policy(struct file *f, const char __user *data,
			     size_t len, loff_t *offset)
{
	int rc = 0;
	bool value = false;
	struct ipe_policy *p = NULL;

	if (!file_ns_capable(f, &init_user_ns, CAP_MAC_ADMIN))
		return -EPERM;

	rc = kstrtobool_from_user(data, len, &value);
	if (rc)
		goto out;

	if (!value) {
		rc = -EINVAL;
		goto out;
	}

	p = ipe_get_policy_rcu(*find_policy(f));
	if (!p) {
		rc = -ENOENT;
		goto out;
	}

	if (ipe_is_policy_active(p)) {
		rc = -EPERM;
		goto out;
	}

	ipe_free_policy(p);
out:
	return (rc < 0) ? rc : len;
}

static const struct file_operations content_fops = {
	.read = read_policy,
};

static const struct file_operations pkcs7_fops = {
	.read = read_pkcs7,
};

static const struct file_operations name_fops = {
	.read = read_name,
};

static const struct file_operations ver_fops = {
	.read = read_version,
};

static const struct file_operations active_fops = {
	.write = setactive,
	.read = getactive,
};

static const struct file_operations update_fops = {
	.write = update_policy,
};

static const struct file_operations delete_fops = {
	.write = delete_policy,
};

/**
 * policy_subdir - files under a policy subdirectory
 */
static const struct ipefs_file policy_subdir[] = {
	{ "pkcs7", 0444, &pkcs7_fops },
	{ "policy", 0444, &content_fops },
	{ "name", 0444, &name_fops },
	{ "version", 0444, &ver_fops },
	{ "active", 0600, &active_fops },
	{ "update", 0200, &update_fops },
	{ "delete", 0200, &delete_fops },
};

/**
 * soft_del_policyfs - soft delete a policyfs node.
 * @p: Supplies a ipe_policy associated with the node to delete.
 *
 * This deletes the i_private field of a policyfs node.
 */
static void soft_del_policyfs(struct ipe_policy *p)
{
	struct inode *ino = NULL;
	struct ipe_policy __rcu **addr = NULL;

	ino = d_inode(p->policyfs);
	addr = (struct ipe_policy __rcu **)&ino->i_private;

	inode_lock(ino);
	rcu_assign_pointer(*addr, NULL);
	inode_unlock(ino);
	synchronize_rcu();
}

/**
 * ipe_del_policyfs_node - Delete a securityfs entry for @p.
 * @p: Supplies a pointer to the policy to delete a securityfs entry for.
 */
void ipe_del_policyfs_node(struct ipe_policy *p)
{
	if (IS_ERR_OR_NULL(p->policyfs))
		return;

	soft_del_policyfs(p);
	securityfs_recursive_remove(p->policyfs);
}

/**
 * ipe_new_policyfs_node - Create a securityfs entry for @p.
 * @p: Supplies a pointer to the policy to create a securityfs entry for.
 *
 * Return:
 * * 0	- OK
 * * !0	- Error
 */
int ipe_new_policyfs_node(struct ipe_policy *p)
{
	int rc = 0;
	size_t i = 0;
	struct dentry *d = NULL;
	struct ipe_policy **addr = NULL;
	const struct ipefs_file *f = NULL;

	p->policyfs = securityfs_create_dir(p->parsed->name, policy_root);
	if (IS_ERR(p->policyfs)) {
		rc = PTR_ERR(p->policyfs);
		goto err;
	}

	addr = (struct ipe_policy **)&(d_inode(p->policyfs)->i_private);
	*addr = p;

	for (i = 0; i < ARRAY_SIZE(policy_subdir); ++i) {
		f = &policy_subdir[i];

		d = securityfs_create_file(f->name, f->access, p->policyfs, p->policyfs,
					   f->fops);
		if (IS_ERR(d)) {
			rc = PTR_ERR(d);
			goto err;
		}
	}

	return 0;
err:
	ipe_del_policyfs_node(p);
	return rc;
}
