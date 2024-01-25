#
# Integrity Policy Enforcement Test Suite
# Copyright (C), Microsoft Corporation, All Rights Reserved.
#
from ipe.templates import IPETestCase
from logging import info
import ipe.util as util
import tempfile
import shutil

_policy_name = "fsverity_verified"

class FSVerityVerifiedTests(IPETestCase):

    def __init__(self, methodName='runtTest', argv={}, tests=set()):
        super(FSVerityVerifiedTests, self).__init__(methodName, argv, tests)
        IPETestCase._allow = str(argv.fsverity)

    @classmethod
    def setUpClass(cls):
        from os import makedirs
        util.activate_ipe_default_policy(cls._securityfs)
        util.ipe_enforce_mode_off(cls._securityfs)
        #create a tmp folder to copy all resources in cls._allow to test deny cases
        cls._tmp = tempfile.mkdtemp()
        util._exec("mount", argv=["-t", "tmpfs", "-o", "size=50m", "tmpfs", cls._tmp], check=True)
        cls._deny = f"{cls._tmp}/deny"
        shutil.copytree(cls._allow, cls._deny)

        if util.ipe_policy_exists(cls._securityfs, _policy_name):
            util.delete_ipe_policy(cls._securityfs, _policy_name)
        util.new_ipe_poilcy(cls._securityfs, f"{cls._policy}/test_func/p7s/fsverity_verified.p7s")
        util.activate_ipe_policy(cls._securityfs, _policy_name)
        util.ipe_enforce_mode_on(cls._securityfs)

    @classmethod
    def tearDownClass(cls):
        util.ipe_enforce_mode_off(cls._securityfs)
        util.activate_ipe_default_policy(cls._securityfs)
        if util.ipe_policy_exists(cls._securityfs, _policy_name):
            util.delete_ipe_policy(cls._securityfs, _policy_name)
        util._exec("umount", argv=[cls._tmp], check=True)
        shutil.rmtree(cls._tmp)
