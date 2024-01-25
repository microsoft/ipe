#
#
# Integrity Policy Enforcement Test Suite 
# Copyright (C), Microsoft Corporation, All Rights Reserved.
#
from logging import exception
import os

def _exec(cmd, argv, env=None, can_fail=False):
    """
        _exec : execute a program that emits plain text output

        @cmd: the command to run
        @argv: the args to add after the commnad
        @can_fail: if false, an exception will be thrown on non-zero error code.

        @rv: (stdout, stderr)
    """
    from subprocess import run
    try:
        ret = run([cmd] + argv, env=env, check=can_fail, universal_newlines=False, capture_output=True)
        return (ret.stdout, ret.stderr)
    except Exception as e:
        cmdline = " ".join([cmd] + argv)
        exception(f"{cmdline}")
        raise e

def _change_ld_rpath(volume_root, bin_path):
    """
        _change_ld_rpath : change the ld and rpath of a binary executable to use the runtime inside volume root

        @volume_root: the path to the runtime resouce directory
        @bin_path: the path to the binary executable

        @rv: None
    """
    _exec("patchelf", ["--set-rpath", f"{volume_root}/lib", bin_path])
    _exec("patchelf", ["--set-interpreter", f"{volume_root}/lib/ld-linux.so", bin_path])

def _change_shebang(volume_root, script_path):
    """
        _change_ld_rpath : change the shebang line of a script to use the runtime inside volume root

        @volume_root: the path to the runtime resouce directory
        @script_path: the path to the script

        @rv: None
    """
    with open(script_path, "r") as f:
        lines = f.readlines()
    lines[0] = f"#!{volume_root}/bin/sh"
    with open(script_path, "w") as f:
        f.write("\n".join(lines))