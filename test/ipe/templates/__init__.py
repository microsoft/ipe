#
# Integrity Policy Enforcement Test Suite
# Copyright (C), Microsoft Corporation, All Rights Reserved.
#
from unittest import TestCase
import logging

LINKER_TEST_KEY     = "linker"
MEMORY_TEST_KEY     = "mem"
SIMPLE_TEST_KEY     = "simple"

PERMISSION_ERROR_CODE = 13


class IPETestCase(TestCase):
    _mnt = None
    _bin = None
    _dev = None
    _securityfs = None
    _policy = None
    _tmp = None
    # _deny is the path to the root of a resource folder, the poilcy will deny the execution of any binary inside the folder
    _deny = None
    # _allow is the path to the root of a resource folder, the poilcy will allow the execution of any binary inside the folder
    _allow = None

    def __init__(self, methodName='runtTest', argv={}, tests=set()):
        super(IPETestCase, self).__init__(methodName)
        IPETestCase._bin = argv.bin_name
        IPETestCase._dev = argv.dev
        IPETestCase._mnt = str(argv.mount_point)
        IPETestCase._securityfs = str(argv.securityfs)
        IPETestCase._policy = str(argv.policy_folder)

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

    def test_smoke_basic_allow(self):
        from ipe.templates.smoke.simple import basic

        if SIMPLE_TEST_KEY not in self.__tests:
            self.skipTest("Simple tests not selected...")

        (returncode, _, stderr) = basic(self._allow)
        if stderr != b'':
            logging.error(f"smoke_basic_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_smoke_basic_deny(self):
        from ipe.templates.smoke.simple import basic

        if SIMPLE_TEST_KEY not in self.__tests:
            self.skipTest("Simple tests not selected...")
        with self.assertRaises(PermissionError):
            basic(self._deny)

    def test_smoke_interpreter_allow(self):
        from ipe.templates.smoke.simple import interpreter

        if SIMPLE_TEST_KEY not in self.__tests:
            self.skipTest("Simple tests not selected...")

        (returncode, _, stderr) = interpreter(self._allow)
        if stderr != b'':
            logging.error(f"smoke_interpreter_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_smoke_interpreter_deny(self):
        from ipe.templates.smoke.simple import interpreter

        if SIMPLE_TEST_KEY not in self.__tests:
            self.skipTest("Simple tests not selected...")

        with self.assertRaises(PermissionError):
            interpreter(self._deny)

    def test_smoke_memfd_deny(self):
        from ipe.templates.smoke.simple import exec_memfd

        if SIMPLE_TEST_KEY not in self.__tests:
            self.skipTest("Simple tests not selected...")

        (returncode, _, _) = exec_memfd(self._allow)
        self.assertEqual(returncode, PERMISSION_ERROR_CODE)

    def test_smoke_ffi_deny(self):
        from ipe.templates.smoke.simple import ffi

        if SIMPLE_TEST_KEY not in self.__tests:
            self.skipTest("Simple tests not selected...")

        with self.assertRaises(MemoryError):
            ffi(self._allow, self._securityfs)

    def test_mem_map_r_allow(self):
        from ipe.templates.mem.mmap import mmap_r

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, stderr) = mmap_r(self._allow, self._allow)
        if stderr != b'':
            logging.error(f"mem_map_r_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)
        (returncode, _, stderr) = mmap_r(self._allow, self._deny)
        if stderr != b'':
            logging.error(f"mem_map_r_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_map_w_allow(self):
        from ipe.templates.mem.mmap import mmap_w

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, stderr) = mmap_w(self._allow, self._allow)
        if stderr != b'':
            logging.error(f"smoke_basic_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)
        (returncode, _, stderr) = mmap_w(self._allow, self._deny)
        if stderr != b'':
            logging.error(f"smoke_basic_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_map_x_allow(self):
        from ipe.templates.mem.mmap import mmap_x

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, stderr) = mmap_x(self._allow, self._allow)
        if stderr != b'':
            logging.error(f"mem_map_x_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_map_x_deny(self):
        from ipe.templates.mem.mmap import mmap_x

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, _) = mmap_x(self._allow, self._deny)
        self.assertEqual(returncode, PERMISSION_ERROR_CODE)

    def test_mem_map_rx_allow(self):
        from ipe.templates.mem.mmap import mmap_rx

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, stderr) = mmap_rx(self._allow, self._allow)
        if stderr != b'':
            logging.error(f"mem_map_rx_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_map_rx_deny(self):
        from ipe.templates.mem.mmap import mmap_rx

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, _) = mmap_rx(self._allow, self._deny)
        self.assertEqual(returncode, PERMISSION_ERROR_CODE)

    def test_mem_map_rw_allow(self):
        from ipe.templates.mem.mmap import mmap_rw

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, stderr) = mmap_rw(self._allow, self._allow)
        if stderr != b'':
            logging.error(f"mem_map_rw_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)
        (returncode, _, stderr) = mmap_rw(self._allow, self._deny)
        if stderr != b'':
            logging.error(f"mem_map_rw_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_map_wx_allow(self):
        from ipe.templates.mem.mmap import mmap_wx

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, stderr) = mmap_wx(self._allow, self._allow)
        if stderr != b'':
            logging.error(f"mem_map_wx_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_map_wx_deny(self):
        from ipe.templates.mem.mmap import mmap_wx

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, _) = mmap_wx(self._allow, self._deny)
        self.assertEqual(returncode, PERMISSION_ERROR_CODE)

    def test_mem_anon_r_allow(self):
        from ipe.templates.mem.mmap import mmap_r_anon

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, stderr) = mmap_r_anon(self._allow)
        if stderr != b'':
            logging.error(f"mem_anon_r_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_anon_w_allow(self):
        from ipe.templates.mem.mmap import mmap_w_anon

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, stderr) = mmap_w_anon(self._allow)
        if stderr != b'':
            logging.error(f"mem_anon_w_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_anon_x_deny(self):
        from ipe.templates.mem.mmap import mmap_x_anon

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, _) = mmap_x_anon(self._allow)
        self.assertEqual(returncode, PERMISSION_ERROR_CODE)

    def test_mem_anon_rw_allow(self):
        from ipe.templates.mem.mmap import mmap_rw_anon

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, stderr) = mmap_rw_anon(self._allow)
        if stderr != b'':
            logging.error(f"mem_anon_rw_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_anon_rx_deny(self):
        from ipe.templates.mem.mmap import mmap_rx_anon

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, _) = mmap_rx_anon(self._allow)
        self.assertEqual(returncode, PERMISSION_ERROR_CODE)


    def test_mem_anon_wx_deny(self):
        from ipe.templates.mem.mmap import mmap_wx_anon

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, _) = mmap_wx_anon(self._allow)
        self.assertEqual(returncode, PERMISSION_ERROR_CODE)


    def test_mem_shared_r_allow(self):
        from ipe.templates.mem.mmap import mmap_r_shared

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, stderr) = mmap_r_shared(self._allow, self._allow)
        if stderr != b'':
            logging.error(f"mem_shared_r_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)
        (returncode, _, stderr) = mmap_r_shared(self._allow, self._deny)
        if stderr != b'':
            logging.error(f"mem_shared_r_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_shared_x_allow(self):
        from ipe.templates.mem.mmap import mmap_x_shared

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, stderr) = mmap_x_shared(self._allow, self._allow)
        if stderr != b'':
            logging.error(f"mem_shared_x_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_shared_x_deny(self):
        from ipe.templates.mem.mmap import mmap_x_shared

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, _) = mmap_x_shared(self._allow, self._deny)
        self.assertEqual(returncode, PERMISSION_ERROR_CODE)


    def test_mem_shared_rx_allow(self):
        from ipe.templates.mem.mmap import mmap_rx_shared

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, stderr) = mmap_rx_shared(self._allow, self._allow)
        if stderr != b'':
            logging.error(f"mem_shared_rx_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)


    def test_mem_shared_rx_deny(self):
        from ipe.templates.mem.mmap import mmap_rx_shared

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, _) = mmap_rx_shared(self._allow, self._deny)
        self.assertEqual(returncode, PERMISSION_ERROR_CODE)

    def test_mem_shared_anon_x_deny(self):
        from ipe.templates.mem.mmap import mmap_x_shared_anon

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, _) = mmap_x_shared_anon(self._allow)
        self.assertEqual(returncode, PERMISSION_ERROR_CODE)


    def test_mem_shared_anon_r_allow(self):
        from ipe.templates.mem.mmap import mmap_r_shared_anon

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, stderr) = mmap_r_shared_anon(self._allow)
        if stderr != b'':
            logging.error(f"mem_shared_anon_r_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_shared_anon_rx_deny(self):
        from ipe.templates.mem.mmap import mmap_rx_shared_anon

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, _) = mmap_rx_shared_anon(self._allow)
        self.assertEqual(returncode, PERMISSION_ERROR_CODE)

    def test_mem_protect_w_x_allow(self):
        from ipe.templates.mem.mprotect import mprotect_w_to_x

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, stderr) = mprotect_w_to_x(self._allow, self._allow)
        if stderr != b'':
            logging.error(f"mem_prtect_w_x with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_protect_w_x_deny(self):
        from ipe.templates.mem.mprotect import mprotect_w_to_x

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, _) = mprotect_w_to_x(self._allow, self._deny)
        self.assertEqual(returncode, PERMISSION_ERROR_CODE)

    def test_mem_protect_w_r_allow(self):
        from ipe.templates.mem.mprotect import mprotect_w_to_r

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, stderr) = mprotect_w_to_r(self._allow, self._allow)
        if stderr != b'':
            logging.error(f"mem_protect_w_r_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)
        (returncode, _, stderr) = mprotect_w_to_r(self._allow, self._deny)
        if stderr != b'':
            logging.error(f"mem_protect_w_r_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_protect_w_rx_allow(self):
        from ipe.templates.mem.mprotect import mprotect_w_to_rx

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, stderr) = mprotect_w_to_rx(self._allow, self._allow)
        if stderr != b'':
            logging.error(f"mem_protect_w_rx_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_protect_w_rx_deny(self):
        from ipe.templates.mem.mprotect import mprotect_w_to_rx

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, _) = mprotect_w_to_rx(self._allow, self._deny)
        self.assertEqual(returncode, PERMISSION_ERROR_CODE)

    def test_mem_protect_r_w_allow(self):
        from ipe.templates.mem.mprotect import mprotect_r_to_w

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, stderr) = mprotect_r_to_w(self._allow, self._allow)
        if stderr != b'':
            logging.error(f"mem_protect_r_w_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)
        (returncode, _, stderr) = mprotect_r_to_w(self._allow, self._deny)
        if stderr != b'':
            logging.error(f"mem_protect_r_w_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_protect_r_x_allow(self):
        from ipe.templates.mem.mprotect import mprotect_r_to_x

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, stderr) = mprotect_r_to_x(self._allow, self._allow)
        if stderr != b'':
            logging.error(f"mem_protect_r_x_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_protect_r_x_deny(self):
        from ipe.templates.mem.mprotect import mprotect_r_to_x

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, _) = mprotect_r_to_x(self._allow, self._deny)
        self.assertEqual(returncode, PERMISSION_ERROR_CODE)

    def test_mem_protect_r_wx_allow(self):
        from ipe.templates.mem.mprotect import mprotect_r_to_wx

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, stderr) = mprotect_r_to_wx(self._allow, self._allow)
        if stderr != b'':
            logging.error(f"mem_protect_r_wx_allow with error messge: {stderr.decode()}")
        self.assertEqual(returncode, 0)

    def test_mem_protect_r_wx_deny(self):
        from ipe.templates.mem.mprotect import mprotect_r_to_wx

        if MEMORY_TEST_KEY not in self.__tests:
            self.skipTest("Memory-based tests not selected...")

        (returncode, _, _) = mprotect_r_to_wx(self._allow, self._deny)
        self.assertEqual(returncode, PERMISSION_ERROR_CODE)

    def test_linker_preload_allow(self):
        from ipe.templates.bypass.linker import ld_preload

        if LINKER_TEST_KEY not in self.__tests:
            self.skipTest("linker-based tests not selected...")

        (_, _, stderr) = ld_preload(self._allow, self._allow)
        #LD_PRELOAD failure won't change return code
        self.assertEqual(stderr, b'')

    def test_linker_preload_deny(self):
        from ipe.templates.bypass.linker import ld_preload

        if LINKER_TEST_KEY not in self.__tests:
            self.skipTest("linker-based tests not selected...")

        (_, _, stderr) = ld_preload(self._allow, self._deny)
        self.assertNotEqual(stderr, b'')

    def test_linker_exec_allow(self):
        from ipe.templates.bypass.linker import ld_exec

        if LINKER_TEST_KEY not in self.__tests:
            self.skipTest("linker-based tests not selected...")

        (returncode, _, _) = ld_exec(self._allow, self._allow, self._allow)
        self.assertEqual(returncode, 0)

    def test_linker_exec_deny(self):
        from ipe.templates.bypass.linker import ld_exec

        if LINKER_TEST_KEY not in self.__tests:
            self.skipTest("linker-based tests not selected...")

        (returncode, _, stderr) = ld_exec(self._allow, self._allow, self._deny)
        self.assertEqual(returncode, 127)
        self.assertNotEqual(stderr, b'')

        (returncode, _, stderr) = ld_exec(self._allow, self._deny, self._allow)
        self.assertEqual(returncode, 127)
        self.assertNotEqual(stderr, b'')

        (returncode, _, stderr) = ld_exec(self._allow, self._deny, self._deny)
        self.assertEqual(returncode, 127)
        self.assertNotEqual(stderr, b'')
