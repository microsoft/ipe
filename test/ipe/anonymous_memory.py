#
# Integrity Policy Enforcement Test Suite
# Copyright (C), Microsoft Corporation, All Rights Reserved.
#
import logging
from unittest import TestCase
import ipe.util as util

_policy_name = "anonymous_memory"

PERMISSION_ERROR_CODE = 13

class AnonymousMemoryTests(TestCase):

    def __init__(self, methodName='runtTest', argv={}):
        super(AnonymousMemoryTests, self).__init__(methodName)
        AnonymousMemoryTests._bin_folder = argv.anon_binary
        AnonymousMemoryTests._securityfs = str(argv.securityfs)
        AnonymousMemoryTests._policy = str(argv.policy_folder)

    @classmethod
    def setUpClass(cls):
        util.activate_ipe_default_policy(cls._securityfs)
        util.ipe_enforce_mode_off(cls._securityfs)

        if util.ipe_policy_exists(cls._securityfs, _policy_name):
            util.delete_ipe_policy(cls._securityfs, _policy_name)
        util.new_ipe_poilcy(cls._securityfs, f"{cls._policy}/test_func/p7s/anonymous_memory.p7s")
        util.activate_ipe_policy(cls._securityfs, _policy_name)
        util.ipe_enforce_mode_on(cls._securityfs)

    @classmethod
    def tearDownClass(cls):
        util.ipe_enforce_mode_off(cls._securityfs)
        util.activate_ipe_default_policy(cls._securityfs)
        if util.ipe_policy_exists(cls._securityfs, _policy_name):
            util.delete_ipe_policy(cls._securityfs, _policy_name)

    @staticmethod
    def build_test(_class, argv):
        from unittest import TestLoader, TestSuite

        loader = TestLoader()
        testnames = loader.getTestCaseNames(_class)
        suite = TestSuite()
        for name in testnames:
            suite.addTest(_class(name, argv=argv))
        return suite

    def test_smoke_basic_allow(self):
        from ipe.templates.smoke.simple import basic

        (returncode, _, stderr) = basic(self._bin_folder)
        if stderr != b'':
            logging.error(f"smoke_basic_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_smoke_interpreter_allow(self):
        from ipe.templates.smoke.simple import interpreter

        (returncode, _, stderr) = interpreter(self._bin_folder)
        if stderr != b'':
            logging.error(f"smoke_interpreter_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_smoke_memfd_deny(self):
        from ipe.templates.smoke.simple import exec_memfd

        (returncode, _, _) = exec_memfd(self._bin_folder)
        self.assertEqual(returncode, PERMISSION_ERROR_CODE)

    def test_smoke_hugepage_memfd_deny(self):
        from ipe.templates.smoke.simple import mmap_exec_hugepage_memfd

        (returncode, _, _) = mmap_exec_hugepage_memfd(self._bin_folder)
        self.assertEqual(returncode, PERMISSION_ERROR_CODE)

    def test_mem_map_r_allow(self):
        from ipe.templates.mem.mmap import mmap_r

        (returncode, _, stderr) = mmap_r(self._bin_folder, self._bin_folder)
        if stderr != b'':
            logging.error(f"mem_map_r_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_map_w_allow(self):
        from ipe.templates.mem.mmap import mmap_w

        (returncode, _, stderr) = mmap_w(self._bin_folder, self._bin_folder)
        if stderr != b'':
            logging.error(f"smoke_basic_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_map_x_allow(self):
        from ipe.templates.mem.mmap import mmap_x

        (returncode, _, stderr) = mmap_x(self._bin_folder, self._bin_folder)
        if stderr != b'':
            logging.error(f"mem_map_x_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_map_rx_allow(self):
        from ipe.templates.mem.mmap import mmap_rx

        (returncode, _, stderr) = mmap_rx(self._bin_folder, self._bin_folder)
        if stderr != b'':
            logging.error(f"mem_map_rx_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_map_rw_allow(self):
        from ipe.templates.mem.mmap import mmap_rw

        (returncode, _, stderr) = mmap_rw(self._bin_folder, self._bin_folder)
        if stderr != b'':
            logging.error(f"mem_map_rw_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_map_wx_allow(self):
        from ipe.templates.mem.mmap import mmap_wx

        (returncode, _, stderr) = mmap_wx(self._bin_folder, self._bin_folder)
        if stderr != b'':
            logging.error(f"mem_map_wx_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_anon_r_allow(self):
        from ipe.templates.mem.mmap import mmap_r_anon

        (returncode, _, stderr) = mmap_r_anon(self._bin_folder)
        if stderr != b'':
            logging.error(f"mem_anon_r_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_anon_w_allow(self):
        from ipe.templates.mem.mmap import mmap_w_anon

        (returncode, _, stderr) = mmap_w_anon(self._bin_folder)
        if stderr != b'':
            logging.error(f"mem_anon_w_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_anon_x_deny(self):
        from ipe.templates.mem.mmap import mmap_x_anon

        (returncode, _, _) = mmap_x_anon(self._bin_folder)
        self.assertEqual(returncode, PERMISSION_ERROR_CODE)

    def test_mem_anon_rw_allow(self):
        from ipe.templates.mem.mmap import mmap_rw_anon

        (returncode, _, stderr) = mmap_rw_anon(self._bin_folder)
        if stderr != b'':
            logging.error(f"mem_anon_rw_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_anon_rx_deny(self):
        from ipe.templates.mem.mmap import mmap_rx_anon

        (returncode, _, _) = mmap_rx_anon(self._bin_folder)
        self.assertEqual(returncode, PERMISSION_ERROR_CODE)

    def test_mem_anon_wx_deny(self):
        from ipe.templates.mem.mmap import mmap_wx_anon

        (returncode, _, _) = mmap_wx_anon(self._bin_folder)
        self.assertEqual(returncode, PERMISSION_ERROR_CODE)


    def test_mem_shared_r_allow(self):
        from ipe.templates.mem.mmap import mmap_r_shared

        (returncode, _, stderr) = mmap_r_shared(self._bin_folder, self._bin_folder)
        if stderr != b'':
            logging.error(f"mem_shared_r_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_shared_x_allow(self):
        from ipe.templates.mem.mmap import mmap_x_shared

        (returncode, _, stderr) = mmap_x_shared(self._bin_folder, self._bin_folder)
        if stderr != b'':
            logging.error(f"mem_shared_x_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_shared_rx_allow(self):
        from ipe.templates.mem.mmap import mmap_rx_shared

        (returncode, _, stderr) = mmap_rx_shared(self._bin_folder, self._bin_folder)
        if stderr != b'':
            logging.error(f"mem_shared_rx_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_shared_anon_x_deny(self):
        from ipe.templates.mem.mmap import mmap_x_shared_anon

        (returncode, _, _) = mmap_x_shared_anon(self._bin_folder)
        self.assertEqual(returncode, PERMISSION_ERROR_CODE)


    def test_mem_shared_anon_r_allow(self):
        from ipe.templates.mem.mmap import mmap_r_shared_anon

        (returncode, _, stderr) = mmap_r_shared_anon(self._bin_folder)
        if stderr != b'':
            logging.error(f"mem_shared_anon_r_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_shared_anon_rx_deny(self):
        from ipe.templates.mem.mmap import mmap_rx_shared_anon

        (returncode, _, _) = mmap_rx_shared_anon(self._bin_folder)
        self.assertEqual(returncode, PERMISSION_ERROR_CODE)

    def test_mem_protect_w_x_allow(self):
        from ipe.templates.mem.mprotect import mprotect_w_to_x

        (returncode, _, stderr) = mprotect_w_to_x(self._bin_folder, self._bin_folder)
        if stderr != b'':
            logging.error(f"mem_prtect_w_x with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_protect_w_r_allow(self):
        from ipe.templates.mem.mprotect import mprotect_w_to_r

        (returncode, _, stderr) = mprotect_w_to_r(self._bin_folder, self._bin_folder)
        if stderr != b'':
            logging.error(f"mem_protect_w_r_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_protect_w_rx_allow(self):
        from ipe.templates.mem.mprotect import mprotect_w_to_rx

        (returncode, _, stderr) = mprotect_w_to_rx(self._bin_folder, self._bin_folder)
        if stderr != b'':
            logging.error(f"mem_protect_w_rx_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_protect_r_w_allow(self):
        from ipe.templates.mem.mprotect import mprotect_r_to_w

        (returncode, _, stderr) = mprotect_r_to_w(self._bin_folder, self._bin_folder)
        if stderr != b'':
            logging.error(f"mem_protect_r_w_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_protect_r_x_allow(self):
        from ipe.templates.mem.mprotect import mprotect_r_to_x

        (returncode, _, stderr) = mprotect_r_to_x(self._bin_folder, self._bin_folder)
        if stderr != b'':
            logging.error(f"mem_protect_r_x_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_protect_r_wx_allow(self):
        from ipe.templates.mem.mprotect import mprotect_r_to_wx

        (returncode, _, stderr) = mprotect_r_to_wx(self._bin_folder, self._bin_folder)
        if stderr != b'':
            logging.error(f"mem_protect_r_wx_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_linker_preload_allow(self):
        from ipe.templates.bypass.linker import ld_preload

        (_, _, stderr) = ld_preload(self._bin_folder, self._bin_folder)
        #LD_PRELOAD failure won't change return code
        self.assertEqual(stderr, b'')

    def test_linker_exec_allow(self):
        from ipe.templates.bypass.linker import ld_exec

        (returncode, _, _) = ld_exec(self._bin_folder, self._bin_folder, self._bin_folder)
        self.assertEqual(returncode, 0)
