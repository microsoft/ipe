#!/usr/bin/python3
#
# Integrity Policy Enforcement Test Suite
# Copyright (C), Microsoft Corporation, All Rights Reserved.
#

def add_test_config(ap):
    from ipe.templates import LINKER_TEST_KEY, MEMORY_TEST_KEY, SIMPLE_TEST_KEY
    from ipe.policy_load import PolicyLoadTests
    test_grp = ap.add_argument_group('tests')
    test_grp.add_argument("--mem",
                          action="append_const",
                          dest="tests",
                          help="Run Memory-based tests",
                          const=MEMORY_TEST_KEY)
    test_grp.add_argument("--simple",
                          action="append_const",
                          dest="tests",
                          help="Run simple tests",
                          const=SIMPLE_TEST_KEY)
    test_grp.add_argument("--linker",
                          action="append_const",
                          dest="tests",
                          help="Run simple tests",
                          const=LINKER_TEST_KEY)
    test_grp.add_argument("--load-policy",
                          action="append_const",
                          dest="tests",
                          help="Run the policy loading tests",
                          const=PolicyLoadTests.test_key)

def add_log_config(ap):
    from pathlib import PurePath
    output_grp = ap.add_argument_group("output")
    output_grp.add_argument("-l", "--log",
                            action="store",
                            dest="log_path",
                            type=PurePath,
                            help="Path to a file to log test output to",
                            default=None)
    output_grp.add_argument("-lvl", "--log-level",
                            action="store",
                            dest="level",
                            type=str,
                            help="Output Log Level",
                            choices=["ERROR", "DEBUG", "INFO", "WARNING", "CRITICAL"],
                            default="ERROR")
    output_grp.add_argument("-q", "--quiet",
                            action="store_true",
                            dest="quiet",
                            help="Suppress all output",
                            default=False)
    output_grp.add_argument("-v", "--verbose",
                            action="store",
                            dest="verbose",
                            type=int,
                            choices=range(1, 3),
                            help="Verbosity Level - this is the test verbosity, which is independent of the log warning level.",
                            default=2)

def parse_config():
    from argparse import ArgumentParser
    from pathlib import PurePath

    ap = ArgumentParser(description="Test Harness for the Integrity Policy Test Suite")
    ap.add_argument("-m", "--mount-point",
                    action="store",
                    dest="mount_point",
                    type=PurePath,
                    help="Path to a folder where the resource folder should be mounted",
                    default="/tmp/ipe-test")
    ap.add_argument("-s", "--securityfs-path",
                    action="store",
                    dest="securityfs",
                    help="Location of securityfs on disk",
                    type=PurePath,
                    default="/sys/kernel/security")
    ap.add_argument("-d", "--dm-dev-name",
                    action="store",
                    dest="dev",\
                    type=str,
                    help="Device name passed to veritysetup. Creates a node of this name under /dev/mapper.",
                    default="ipe")
    ap.add_argument("-n", "--res-bin-name",
                    action="store",
                    dest="bin_name",
                    type=PurePath,
                    help="Resource binary common prefix. This will be used as {bin_name}.(squashfs|hashtree|roothash|p7s)")
    ap.add_argument("-p", "--policy_folder",
                    action="store",
                    dest="policy_folder",
                    type=PurePath,
                    required=True)
    ap.add_argument("-f", "--fsverity_verified_folder",
                    action="store",
                    dest="fsverity",
                    type=PurePath,
                    help="Path to the bin resouces to test fsverity verified, the fsverity verified tests will only run when this path is set")

    add_log_config(ap)
    add_test_config(ap)

    return ap.parse_args()

def setup_logging(argv):
    import logging
    from logging import basicConfig
    from os import devnull
    from sys import stderr
    LOG_FORMAT_STRING = "%(levelname)s %(asctime)s %(message)s"
    ISO_8601 = "%G-%m-%dT%H:%M:%S%z"

    if argv.quiet:
        logging.basicConfig(filename=devnull, format=LOG_FORMAT_STRING, datefmt=ISO_8601, level=getattr(logging, argv.level))
    elif argv.log_path != None:
        logging.basicConfig(filename=argv.log_path, format=LOG_FORMAT_STRING, datefmt=ISO_8601, level=getattr(logging, argv.level))
    else:
        logging.basicConfig(stream=stderr, format=LOG_FORMAT_STRING, datefmt=ISO_8601, level=getattr(logging, argv.level))

def map_tests(argv):

    if argv.tests == None:
        return set(["simple", "mem", "linker"])
    else:
        return set(argv.tests)

def add_test(subclass, argv, tests):
    return IPETestCase.build_test(subclass, argv=argv, tests=tests)

if __name__ == "__main__":
    from logging import debug
    from sys import stdout
    from ipe.templates import IPETestCase
    from ipe.dmverity_verified import DMVerityVerifiedTests
    from ipe.dmverity_roothash import DMVerityRootHashTests
    from ipe.fsverity_verified import FSVerityVerifiedTests
    from ipe.fsverity_measurement import FSVerityMeasurementTests
    from ipe.policy_load import PolicyLoadTests
    from unittest import TextTestRunner, TestSuite

    argv = parse_config()

    setup_logging(argv)
    enabled_tests = map_tests(argv)

    debug(f"mount_point: { argv.mount_point}")
    debug(f"securityfs: {argv.securityfs}")
    debug(f"dev_name: {argv.dev}")
    debug(f"binary_prefix: {argv.bin_name}")
    debug(f"tests: {enabled_tests}")
    debug(f"verbosity: {argv.verbose}")

    runner = TextTestRunner(stream=stdout if not argv.quiet else None,
                            verbosity=argv.verbose)
    tests = TestSuite()

    tests.addTest(PolicyLoadTests.build_test(PolicyLoadTests, argv=argv, tests=enabled_tests))
    #Only add the tests when the required argument is provided
    if not argv.bin_name is None:
        tests.addTest(add_test(DMVerityRootHashTests, argv, enabled_tests))
        tests.addTest(add_test(DMVerityVerifiedTests, argv, enabled_tests))
    if not argv.fsverity is None:
        tests.addTest(add_test(FSVerityVerifiedTests, argv, enabled_tests))
        tests.addTest(add_test(FSVerityMeasurementTests, argv, enabled_tests))

    runner.run(tests)
