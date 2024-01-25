#!/usr/bin/python3
#
# Integrity Policy Enforcement Test Suite
# Copyright (C), Microsoft Corporation, All Rights Reserved.
#

def parse_config():
    from argparse import ArgumentParser
    from pathlib import PurePath

    ap = ArgumentParser(description="Policy roothash updating tool for the Integrity Policy Test Suite")
    ap.add_argument("-p", "--policy_folder",
    action="store",
    dest="policy_folder",
    type=PurePath,
    help="Path to the policy folder",
    required=True)
    ap.add_argument("-r", "--roothash",
    action="store",
    dest="roothash",
    type=PurePath,
    help="Path to the volume roothash file",
    required=True)

    return ap.parse_args()

def update_policy_roothash(argv):
    import re
    policy_file_path = f"{argv.policy_folder}/test_func/text/dmverity_roothash.pol"
    roothash_file_path = str(argv.roothash)
    with open(roothash_file_path, "r") as f:
        roothash = f.read()
    with open(policy_file_path, "r") as f:
        policy_file_content = f.read()

    print(roothash)
    updated_policy_file_content = re.sub(r'dmverity_roothash=[\w:]+', f"dmverity_roothash=sha256:{roothash}", policy_file_content)
    with open(policy_file_path, "w") as f:
        f.write(updated_policy_file_content)

if __name__ == "__main__":
    argv = parse_config()
    update_policy_roothash(argv)

    print("Roothash inside the policy has been updated, please sign the updated policy before running the tests")
