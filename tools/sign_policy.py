#!/usr/bin/python3
#
# Integrity Policy Enforcement Test Suite
# Copyright (C), Microsoft Corporation, All Rights Reserved.
#
from util import _exec

def parse_config():
    from argparse import ArgumentParser
    from pathlib import PurePath

    ap = ArgumentParser(description="Policy signing tool for the Integrity Policy Test Suite")
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
    ap.add_argument("-p", "--policy_folder",
    action="store",
    dest="policy_folder",
    type=PurePath,
    help="Path to the policy folder",
    required=True)

    return ap.parse_args()

def sign_policies(directory, argv):
    import glob
    import os

    policy_paths = (glob.glob(f"{directory}/text/*.pol"))
    policy_names = [os.path.splitext(os.path.basename(path))[0] for path in policy_paths]
    signed_policy_paths = [f"{directory}/p7s/{name}.p7s" for name in policy_names]
    if not os.path.exists(f"{directory}/p7s"):
        os.mkdir(f"{directory}/p7s")
    for path_pair in zip(policy_paths, signed_policy_paths):
        _exec("openssl", ["smime", "-sign", "-signer", argv.cert, "-inkey", argv.key, "-nodetach", "-noattr",
        "-binary", "-outform", "der", "-in", path_pair[0], "-out", path_pair[1]])

if __name__ == "__main__":
    argv = parse_config()
    policy_folder = str(argv.policy_folder)
    sign_policies(f"{policy_folder}/test_load", argv)
    sign_policies(f"{policy_folder}/test_func", argv)