#
#
# Integrity Policy Enforcement Test Suite
# Copyright (C), Microsoft Corporation, All Rights Reserved.
#
import os
import logging

_default_policy_name = "allow_all"

def _exec(cmd, argv, env=None, check=False):
    """
        exec : execute a program that emits plain text output

        @cmd: the command to run
        @argv: the args to add after the commnad
        @check: if True, an exception will be thrown on non-zero error code.

        @rv: (returncode, stdout, stderr)
    """
    from subprocess import run
    ret = run([cmd] + argv, env=env, check=check,
              universal_newlines=False, capture_output=True)
    cmdline = " ".join([cmd] + argv)
    logging.debug(f"Command \"{cmdline}\" returns {ret}")
    return (ret.returncode, ret.stdout, ret.stderr)


def new_ipe_poilcy(securityfs_root, policy_path):
    """
        new_ipe_policy : add a new ipe policy from a file

        @securityfs_root: the path to the root of securityfs
        @policy_path: the path to the new policy file

        @rv: None
    """
    logging.debug(f"Prepare to add new policy {policy_path}")
    content = None
    with open(policy_path, "rb") as f:
        content = f.read()
    with open(f"{securityfs_root}/ipe/new_policy", "wb") as f:
        f.write(content)
    logging.debug(f"New policy {policy_path} added")

def update_ipe_policy(securityfs_root, policy_name, policy_path):
    """
        update_ipe_policy : update an exsiting ipe policy from a file

        @securityfs_root: the path to the root of securityfs
        @policy name: the name of policy to be updated
        @policy_path: the path to the new policy file

        @rv: None
    """
    logging.debug(f"Prepare to update policy {policy_name} with file {policy_path}")
    content = None
    with open(policy_path, "rb") as f:
        content = f.read()
    with open(f"{securityfs_root}/ipe/policies/{policy_name}/update", "wb") as f:
        f.write(content)
    logging.debug(f"Update policy {policy_name} with file {policy_path} finished")

def delete_ipe_policy(securityfs_root, policy_name):
    """
        delete_ipe_policy : delete an exsiting policy

        @securityfs_root: the path to the root of securityfs
        @policy name: the name of policy to be deleted

        @rv: None
    """
    logging.debug(f"Prepare to delete policy {policy_name}")
    with open(f"{securityfs_root}/ipe/policies/{policy_name}/delete", "wb") as f:
        #write "1\0"
        f.write(b'\x31\x00')
    logging.debug(f"policy {policy_name} deleted")

def ipe_policy_exists(securityfs_root, policy_name):
    """
        ipe_policy_exists : query if a policy exits in the current state

        @securityfs_root: the path to the root of securityfs
        @policy name: the name of policy to be queried

        @rv: None
    """
    return os.path.exists(f"{securityfs_root}/ipe/policies/{policy_name}")

def activate_ipe_policy(securityfs_root, policy_name):
    """
        activate_ipe_policy : deploy the policy referenced by @policy_name
        to the IPE subsystesm, making it the actisve policy

        @securityfs_root: the path to the root of securityfs
        @policy name: the name of policy to be deployed

        @rv: None
    """
    logging.debug(f"Prepare to activate policy {policy_name}")
    with open(f"{securityfs_root}/ipe/policies/{policy_name}/active", "wb") as f:
        #write "1\0"
        f.write(b'\x31\x00')
    logging.debug(f"Policy {policy_name} activatied")

def activate_ipe_default_policy(securityfs_root):
    """
        activate_ipe_default_policy : switch the default ipe policy(i.e. allow all)
    """
    activate_ipe_policy(securityfs_root, _default_policy_name)

def ipe_enforce_mode_on(securityfs_root):
    """
        ipe_enforce_mode_on : switch the ipe enforce mode on
    """
    with open(f"{securityfs_root}/ipe/enforce", "wb") as f:
        #write "1\0"
        f.write(b'\x31\x00')
    logging.debug(f"IPE enforce mode on")

def ipe_enforce_mode_off(securityfs_root):
    """
        ipe_enforce_mode_off : switch the ipe enforce mode off
    """
    with open(f"{securityfs_root}/ipe/enforce", "wb") as f:
        #write "0\0"
        f.write(b'\x30\x00')
    logging.debug(f"IPE enforce mode off")
