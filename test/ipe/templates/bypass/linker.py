#
# Integrity Policy Enforcement Test Suite 
# Copyright (C), Microsoft Corporation, All Rights Reserved.
#
import ipe.util as util

def ld_preload(bin_path, lib_path):
    """
    ld_preload:
      invoke a binary in @bin_path with ld-preload set to a custom library
      under @lib_path.

    Returns the return code and outputs of the helper binary.

    @path: path to the root of the test resource folder
    @rv: (return code, stdout, stderr)
    """
    return util._exec(f"{bin_path}/bin/hello" ,[], env={"LD_PRELOAD": f"{lib_path}/lib/libhello.so"})

def ld_exec(ld_path, bin_path, lib_path):
    """
    ld_exec:
      invoke a binary via /lib/ld-<version>, loading in into a process
      without directly executing it.

    Returns the return code and outputs of the binary

    @ld_path: path to the root of the test resource folder contains ld-linux.so
    @bin_path: path to the root of the test resource folder contains helper binary
    @lib_path: path to the root of the test resource folder contains library binary
    @rv: (return code, stdout, stderr)
    """
    return util._exec(f"{ld_path}/lib/ld-linux.so" ,["--library-path", f"{lib_path}/lib", f"{bin_path}/bin/hello"])
