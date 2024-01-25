#
# Integrity Policy Enforcement Test Suite
# Copyright (C), Microsoft Corporation, All Rights Reserved.
#
from ipe.templates import IPETestCase
from logging import info
import ipe.util as util
import tempfile
import shutil

_policy_name = "dmverity_verified"

class DMVerityVerifiedTests(IPETestCase):

    @classmethod
    def setUpClass(cls):
        """
            setUpClass : standard setup for a dmverity-based test.
            Performs the following:
                1. Mount the test.squashfs volume to /dev/mapper/{cls._dev}
                2. Mount the mapped volume to cls._mnt
                3. Swap the policy to the policy under test (PUT)

            @rv: None
        """
        from os import makedirs
        util.activate_ipe_default_policy(cls._securityfs)
        util.ipe_enforce_mode_off(cls._securityfs)
        root_hash = None
        with open(f"{cls._bin}.roothash", "r") as f:
            root_hash = f.readline()
        info(f"Creating DM Device {cls._dev} from {cls._bin}.squashfs, {cls._bin}.hashtree")
        util._exec("veritysetup", argv=["open",
                                    f"{cls._bin}.squashfs",
                                    f"{cls._dev}",
                                    f"{cls._bin}.hashtree",
                                    root_hash,
                                    f"--root-hash-signature={cls._bin}.p7s"],
                                    check=True)
        makedirs(cls._mnt, exist_ok=True)
        info(f"Mounting /dev/mapper/{cls._dev}")
        util._exec("mount", argv=[f"/dev/mapper/{cls._dev}", str(cls._mnt)])
        cls._allow = cls._mnt
        #create a tmp folder to copy all resources in cls._mnt to test deny cases
        cls._tmp = tempfile.mkdtemp()
        cls._deny = f"{cls._tmp}/deny"
        shutil.copytree(cls._allow, cls._deny)

        if util.ipe_policy_exists(cls._securityfs, _policy_name):
            util.delete_ipe_policy(cls._securityfs, _policy_name)
        util.new_ipe_poilcy(cls._securityfs, f"{cls._policy}/test_func/p7s/dmverity_verified.p7s")
        util.activate_ipe_policy(cls._securityfs, _policy_name)
        util.ipe_enforce_mode_on(cls._securityfs)

    @classmethod
    def tearDownClass(cls):
        """
            setUpClass : standard cleanup for a dmverity-based test.
            Performs the following:
                1. Swap the policy to the original policy
                2. Unmount the mapped volume to cls._mnt
                3. Unmap the test.squashfs volume from /dev/mapper/{cls._dev}

            @rv: None
        """
        util.ipe_enforce_mode_off(cls._securityfs)
        util.activate_ipe_default_policy(cls._securityfs)
        from os import rmdir
        util._exec("umount", argv=[cls._mnt], check=True)
        rmdir(cls._mnt)
        util._exec("veritysetup", argv=["close", cls._dev], check=True)
        if util.ipe_policy_exists(cls._securityfs, _policy_name):
            util.delete_ipe_policy(cls._securityfs, _policy_name)
        shutil.rmtree(cls._tmp)
