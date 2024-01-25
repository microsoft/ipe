#
# Integrity Policy Enforcement Test Suite
# Copyright (C), Microsoft Corporation, All Rights Reserved.
#
from unittest import TestCase
import ipe.util as util
import os

class PolicyLoadTests(TestCase):
    __securityfs = None
    __policy_folder = None
    __test_policy_name = "Test_Policy"

    test_key = 'policy_load'

    def __init__(self, methodName='runTest', argv={}, tests=set()):
        super(PolicyLoadTests, self).__init__(methodName)
        PolicyLoadTests.__securityfs = argv.securityfs
        PolicyLoadTests.__policy_folder = argv.policy_folder

        self.__tests = tests

    @staticmethod
    def build_test(_class, argv, tests):
        from unittest import TestLoader, TestSuite

        loader = TestLoader()
        testnames = loader.getTestCaseNames(_class)
        suite = TestSuite()
        for name in testnames:
            suite.addTest(_class(name, argv=argv, tests=tests))
        return suite

    def skip_if_not_enabled(self):
        if PolicyLoadTests.test_key not in self.__tests:
            self.skipTest("Policy load tests not specified to run...")

    def setUp(self):
        util.activate_ipe_default_policy(self.__securityfs)
        if util.ipe_policy_exists(self.__securityfs, self.__test_policy_name):
            util.delete_ipe_policy(self.__securityfs, self.__test_policy_name)

    def tearDown(self):
        if util.ipe_policy_exists(self.__securityfs, self.__test_policy_name):
            util.delete_ipe_policy(self.__securityfs, self.__test_policy_name)

    def get_policy_path(self, policy_file_name):
        return f"{self.__policy_folder}/test_load/p7s/{policy_file_name}"

    def test_load_allow_all_pass(self):
        self.skip_if_not_enabled()
        policy_file_name = "allowall.p7s"
        util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))

    def test_load_newline_pass(self):
        self.skip_if_not_enabled()
        policy_file_name = "allowallnewline.p7s"
        util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))

    def test_load_comprehensive_pass(self):
        self.skip_if_not_enabled()
        policy_file_name = "comprehensive.p7s"
        util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))

    def test_load_boot_verified_pass(self):
        self.skip_if_not_enabled()
        policy_file_name = "bootverified.p7s"
        util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))

    def test_load_bootv_dmv_pass(self):
        self.skip_if_not_enabled()
        policy_file_name = "bootvdmv.p7s"
        util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))

    def test_denyall_pass(self):
        self.skip_if_not_enabled()
        policy_file_name = "denyall.p7s"
        util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))

    def test_extra_space_pass(self):
        self.skip_if_not_enabled()
        policy_file_name = "extraspace.p7s"
        util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))

    def test_nested_default_pass(self):
        self.skip_if_not_enabled()
        policy_file_name = "nesteddefault.p7s"
        util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))

    def test_special_name_pass(self):
        self.skip_if_not_enabled()
        util.activate_ipe_default_policy(self.__securityfs)
        if util.ipe_policy_exists(self.__securityfs, "Test_Policy$"):
            util.delete_ipe_policy(self.__securityfs, "Test_Policy$")
        util.new_ipe_poilcy(self.__securityfs, self.get_policy_path("specialpolicyname0.p7s"))
        util.delete_ipe_policy(self.__securityfs, "Test_Policy$")
        # "/" not in special char since it is not allowed to be used inside a directory name
        if util.ipe_policy_exists(self.__securityfs, r")(*&^%$@!+-';:><.,\][`~"):
            util.delete_ipe_policy(self.__securityfs, r")(*&^%$@!+-';:><.,\][`~")
        util.new_ipe_poilcy(self.__securityfs, self.get_policy_path("specialpolicyname1.p7s"))
        util.delete_ipe_policy(self.__securityfs, r")(*&^%$@!+-';:><.,\][`~")

    def test_allowall_comment_pass(self):
        self.skip_if_not_enabled()
        policy_file_name = "allowallcomment.p7s"
        util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))

    def test_extra_ver_fail(self):
        self.skip_if_not_enabled()
        policy_file_name = "extraver.p7s"
        with self.assertRaises(OSError):
            util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))

    def test_incomplete_ver_fail(self):
        self.skip_if_not_enabled()
        policy_file_name = "incompletever0.p7s"
        with self.assertRaises(OSError):
            util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))
        policy_file_name = "incompletever1.p7s"
        with self.assertRaises(OSError):
            util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))
        policy_file_name = "incompletever2.p7s"
        with self.assertRaises(OSError):
            util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))
        policy_file_name = "incompletever3.p7s"
        with self.assertRaises(OSError):
            util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))

    def test_incomplete_rule_fail(self):
        self.skip_if_not_enabled()
        policy_file_name = "incompleterule0.p7s"
        with self.assertRaises(OSError):
            util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))
        policy_file_name = "incompleterule1.p7s"
        with self.assertRaises(OSError):
            util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))

    def test_incomplete_header_fail(self):
        self.skip_if_not_enabled()
        policy_file_name = "incompleteheader0.p7s"
        with self.assertRaises(OSError):
            util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))
        policy_file_name = "incompleteheader1.p7s"
        with self.assertRaises(OSError):
            util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))
        policy_file_name = "incompleteheader2.p7s"
        with self.assertRaises(OSError):
            util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))
        policy_file_name = "incompleteheader3.p7s"
        with self.assertRaises(OSError):
            util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))
        policy_file_name = "incompleteheader4.p7s"
        with self.assertRaises(OSError):
            util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))

    def test_malformed_header_fail(self):
        self.skip_if_not_enabled()
        policy_file_name = "malformedheader0.p7s"
        with self.assertRaises(OSError):
            util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))
        policy_file_name = "malformedheader1.p7s"
        with self.assertRaises(OSError):
            util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))

    def test_negative_version_fail(self):
        self.skip_if_not_enabled()
        policy_file_name = "negtiveversion.p7s"
        with self.assertRaises(OSError):
            util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))

    def test_no_policy_fail(self):
        self.skip_if_not_enabled()
        policy_file_name = "nopolicy.p7s"
        with self.assertRaises(OSError):
            util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))

    def test_anti_rollback(self):
        self.skip_if_not_enabled()
        util.new_ipe_poilcy(self.__securityfs, self.get_policy_path("version0.p7s"))

        util.update_ipe_policy(self.__securityfs, self.__test_policy_name, self.get_policy_path("version1.p7s"))
        with self.assertRaises(OSError):
            util.update_ipe_policy(self.__securityfs, self.__test_policy_name, self.get_policy_path("version0.p7s"))

        util.update_ipe_policy(self.__securityfs, self.__test_policy_name, self.get_policy_path("version5.6.898.p7s"))
        with self.assertRaises(OSError):
            util.update_ipe_policy(self.__securityfs, self.__test_policy_name, self.get_policy_path("version0.p7s"))
        with self.assertRaises(OSError):
            util.update_ipe_policy(self.__securityfs, self.__test_policy_name, self.get_policy_path("version1.p7s"))

        util.update_ipe_policy(self.__securityfs, self.__test_policy_name, self.get_policy_path("version6.8.28.p7s"))
        with self.assertRaises(OSError):
            util.update_ipe_policy(self.__securityfs, self.__test_policy_name, self.get_policy_path("version0.p7s"))
        with self.assertRaises(OSError):
            util.update_ipe_policy(self.__securityfs, self.__test_policy_name, self.get_policy_path("version1.p7s"))
        with self.assertRaises(OSError):
            util.update_ipe_policy(self.__securityfs, self.__test_policy_name, self.get_policy_path("version5.6.898.p7s"))

        util.update_ipe_policy(self.__securityfs, self.__test_policy_name, self.get_policy_path("version6.8.123.p7s"))
        with self.assertRaises(OSError):
            util.update_ipe_policy(self.__securityfs, self.__test_policy_name, self.get_policy_path("version0.p7s"))
        with self.assertRaises(OSError):
            util.update_ipe_policy(self.__securityfs, self.__test_policy_name, self.get_policy_path("version1.p7s"))
        with self.assertRaises(OSError):
            util.update_ipe_policy(self.__securityfs, self.__test_policy_name, self.get_policy_path("version5.6.898.p7s"))
        with self.assertRaises(OSError):
            util.update_ipe_policy(self.__securityfs, self.__test_policy_name, self.get_policy_path("version6.8.28.p7s"))

        util.update_ipe_policy(self.__securityfs, self.__test_policy_name, self.get_policy_path("version6.8.124.p7s"))
        with self.assertRaises(OSError):
            util.update_ipe_policy(self.__securityfs, self.__test_policy_name, self.get_policy_path("version0.p7s"))
        with self.assertRaises(OSError):
            util.update_ipe_policy(self.__securityfs, self.__test_policy_name, self.get_policy_path("version1.p7s"))
        with self.assertRaises(OSError):
            util.update_ipe_policy(self.__securityfs, self.__test_policy_name, self.get_policy_path("version5.6.898.p7s"))
        with self.assertRaises(OSError):
            util.update_ipe_policy(self.__securityfs, self.__test_policy_name, self.get_policy_path("version6.8.28.p7s"))
        with self.assertRaises(OSError):
            util.update_ipe_policy(self.__securityfs, self.__test_policy_name, self.get_policy_path("version6.8.123.p7s"))

        util.update_ipe_policy(self.__securityfs, self.__test_policy_name, self.get_policy_path("version7.0.0.p7s"))
        with self.assertRaises(OSError):
            util.update_ipe_policy(self.__securityfs, self.__test_policy_name, self.get_policy_path("version0.p7s"))
        with self.assertRaises(OSError):
            util.update_ipe_policy(self.__securityfs, self.__test_policy_name, self.get_policy_path("version1.p7s"))
        with self.assertRaises(OSError):
            util.update_ipe_policy(self.__securityfs, self.__test_policy_name, self.get_policy_path("version5.6.898.p7s"))
        with self.assertRaises(OSError):
            util.update_ipe_policy(self.__securityfs, self.__test_policy_name, self.get_policy_path("version6.8.28.p7s"))
        with self.assertRaises(OSError):
            util.update_ipe_policy(self.__securityfs, self.__test_policy_name, self.get_policy_path("version6.8.123.p7s"))
        with self.assertRaises(OSError):
            util.update_ipe_policy(self.__securityfs, self.__test_policy_name, self.get_policy_path("version6.8.124.p7s"))

    def test_not_implemented_property_fail(self):
        self.skip_if_not_enabled()
        policy_file_name = "notimplementedproperty.p7s"
        with self.assertRaises(OSError):
            util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))

    def test_default_with_property_fail(self):
        self.skip_if_not_enabled()
        policy_file_name = "defaultwithproperty0.p7s"
        with self.assertRaises(OSError):
            util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))
        policy_file_name = "defaultwithproperty1.p7s"
        with self.assertRaises(OSError):
            util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))

    def test_invalid_op_fail(self):
        self.skip_if_not_enabled()
        policy_file_name = "invalidop.p7s"
        with self.assertRaises(OSError):
            util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))

    def test_invalid_action_fail(self):
        self.skip_if_not_enabled()
        policy_file_name = "invalidaction.p7s"
        with self.assertRaises(OSError):
            util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))

    def test_double_default_fail(self):
        self.skip_if_not_enabled()
        policy_file_name = "doubledefault0.p7s"
        with self.assertRaises(OSError):
            util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))
        policy_file_name = "doubledefault1.p7s"
        with self.assertRaises(OSError):
            util.new_ipe_poilcy(self.__securityfs, self.get_policy_path(policy_file_name))
