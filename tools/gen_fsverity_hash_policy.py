
#!/usr/bin/python3
#
# Integrity Policy Enforcement Test Suite
# Copyright (C), Microsoft Corporation, All Rights Reserved.
#

def parse_config():
    from argparse import ArgumentParser
    from pathlib import PurePath

    ap = ArgumentParser(description="Policy generating tool for the fsverity test of the Integrity Policy Test Suite")
    ap.add_argument("-p", "--policy_folder",
    action="store",
    dest="policy_folder",
    type=PurePath,
    help="Path to the policy folder",
    required=True)
    ap.add_argument("-v", "--fsverity_folder",
    action="store",
    dest="fsverity_folder",
    type=PurePath,
    help="Path to the folder contains files enabled fsverity",
    required=True)

    return ap.parse_args()

def get_fsv_measurement(file_path):
    from util import _exec
    import re
    output = _exec("fsverity", ["measure", file_path])[0].decode('utf-8')
    return re.match("sha256:(?P<hash>\w+)", output).group('hash')


def gen_policy(argv):
    import glob
    import os

    sig_paths = (glob.glob(f"{argv.fsverity_folder}/*/*.sig"))
    file_paths = [os.path.splitext(s)[0] for s in sig_paths]
    file_hashs = [get_fsv_measurement(f) for f in file_paths]

    policy_file_path = f"{argv.policy_folder}/test_func/text/fsverity_measurement.pol"
    policy_text = "policy_name=fsverity_measurement policy_version=0.0.0\nDEFAULT action=DENY\n"
    for file_path, file_hash in zip(file_paths, file_hashs):
        policy_text += f"#{file_path}\n"
        policy_text += f"op=EXECUTE fsverity_digest=sha256:{file_hash} action=ALLOW\n"

    with open(policy_file_path, "w") as f:
        f.write(policy_text)

if __name__ == "__main__":
    argv = parse_config()
    gen_policy(argv)

    print("Policy for fsverity test has been updated, please sign the policy before running the tests")
