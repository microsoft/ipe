#!/usr/bin/python3
#
# Integrity Policy Enforcement Test Suite
# Copyright (C), Microsoft Corporation, All Rights Reserved.
#
from util import _exec, _change_ld_rpath, _change_shebang

def parse_config():
    from argparse import ArgumentParser
    from pathlib import PurePath

    ap = ArgumentParser(
        description="Resouce folder formating tool for the Integrity Policy Test Suite")
    ap.add_argument("-d", "--directory",
                    action="store",
                    dest="directory",
                    type=PurePath,
                    help="Path to the folder that contains the volume data",
                    required=True)
    ap.add_argument("-v", "--verified-mount-point",
                    action="store",
                    dest="test_path",
                    type=PurePath,
                    help="Path to a folder where the resource folder will be appeared during the test",
                    required=True)

    return ap.parse_args()

def format_volume(argv):
    import os
    import glob

    directory = str(os.path.abspath(argv.directory))
    test_path = str(os.path.abspath(argv.test_path))

    if not os.path.exists(directory):
        raise FileNotFoundError(directory)
    bin_paths = (glob.glob(f"{directory}/bin/*"))
    script_paths = (glob.glob(f"{directory}/script/*"))

    for bin_path in bin_paths:
        _change_ld_rpath(test_path, bin_path)
    for script_path in script_paths:
        _change_shebang(test_path, script_path)

if __name__ == "__main__":
    argv = parse_config()
    format_volume(argv)
