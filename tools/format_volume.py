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
        description="Volume formating tool for the Integrity Policy Test Suite")
    ap.add_argument("-o", "--output",
                    action="store",
                    dest="output",
                    type=PurePath,
                    help="output directory",
                    required=True)
    ap.add_argument("-d", "--directory",
                    action="store",
                    dest="directory",
                    type=PurePath,
                    help="Path to the folder that contains the volume data",
                    required=True)
    ap.add_argument("-k", "--key",
                    action="store",
                    dest="key",
                    type=PurePath,
                    help="Path to the signer's private key",
                    required=True)
    ap.add_argument("-c", "--cert",
                    action="store",
                    dest="cert",
                    type=PurePath,
                    help="Path to the signer's certification",
                    required=True)
    ap.add_argument("-m", "--mount-point",
                    action="store",
                    dest="mount_point",
                    type=PurePath,
                    help="Path to a folder where the resource folder should be mounted",
                    default="/tmp/ipe-test")

    return ap.parse_args()

def format_volume(argv):
    import os
    import glob

    directory = str(os.path.abspath(argv.directory))
    output = str(os.path.abspath(argv.output))
    mnt = str(argv.mount_point)

    if not os.path.exists(directory):
        raise FileNotFoundError(directory)
    if not os.path.exists(output):
        raise FileNotFoundError(output)
    if not os.path.isdir(output):
        raise Exception(f"{output} is not a directory")
    basename = os.path.basename(directory)
    bin_paths = (glob.glob(f"{directory}/bin/*"))
    script_paths = (glob.glob(f"{directory}/script/*"))

    for bin_path in bin_paths:
        _change_ld_rpath(mnt, bin_path)
    for script_path in script_paths:
        _change_shebang(mnt, script_path)

    old_file_paths = (glob.glob(f"{output}/{basename}.*"))
    for old_file_path in old_file_paths:
        os.remove(old_file_path)

    _exec("mksquashfs", [directory, f"{output}/{basename}.squashfs"])
    _exec("veritysetup", ["format", "--root-hash-file", f"{output}/{basename}.roothash", f"{output}/{basename}.squashfs", f"{output}/{basename}.hashtree"])
    _exec("openssl", ["smime", "-sign", "-signer", argv.cert, "-inkey", argv.key, "-noattr",
        "-binary", "-outform", "der", "-in", f"{output}/{basename}.roothash", "-out", f"{output}/{basename}.p7s"])

    for bin_path in bin_paths:
        _change_ld_rpath(directory, bin_path)
    for script_path in script_paths:
        _change_shebang(directory, script_path)

if __name__ == "__main__":
    argv = parse_config()
    format_volume(argv)
