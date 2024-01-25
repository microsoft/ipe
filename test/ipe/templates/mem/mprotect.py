#
# Integrity Policy Enforcement Test Suite 
# Copyright (C), Microsoft Corporation, All Rights Reserved.
#
import ipe.util as util

def mprotect_w_to_x(mproect_path, bin_path):
    """
    mprotect_w_to_x:
      Map a file/binary under @bin_path with PROT_WRITE permissions,
      then change the permissions to PROT_EXEC.

    Returns the return code of mprotect and the output of helper binary

    @mprotect_path: path to the root of the test resource folder contains mprotect helper binary
    @bin_path: path to the root of the test resource folder contains file to be mapped
    @rv: (return code, stdout, stderr)
    """
    return util._exec(f"{mproect_path}/bin/mprotect_test", ["w", "x", f"{bin_path}/bin/hello"])

def mprotect_w_to_r(mproect_path, bin_path):
    """
    mprotect_w_to_r:
      Map a file/binary under @bin_path with PROT_WRITE permissions,
      then change the permissions to PROT_EXEC.

    Returns the return code of mprotect and the output of helper binary

    @mprotect_path: path to the root of the test resource folder contains mprotect helper binary
    @bin_path: path to the root of the test resource folder contains file to be mapped
    @rv: (return code, stdout, stderr)
    """
    return util._exec(f"{mproect_path}/bin/mprotect_test", ["w", "r", f"{bin_path}/bin/hello"])

def mprotect_w_to_rx(mproect_path, bin_path):
    """
    mprotect_w_to_rx:
      Map a file/binary under @path with PROT_WRITE permissions,
      then change the permissions to PROT_READ and PROT_EXEC.

    Returns the return code of mprotect and the output of helper binary

    @mprotect_path: path to the root of the test resource folder contains mprotect helper binary
    @bin_path: path to the root of the test resource folder contains file to be mapped
    @rv: (return code, stdout, stderr)
    """
    return util._exec(f"{mproect_path}/bin/mprotect_test", ["w", "rx", f"{bin_path}/bin/hello"])

def mprotect_r_to_w(mproect_path, bin_path):
    """
    mprotect_r_to_w:
      Map a file/binary under @path with PROT_READ permissions,
      then change the permissions to PROT_WRITE.

    Returns the return code of mprotect and the output of helper binary

    @mprotect_path: path to the root of the test resource folder contains mprotect helper binary
    @bin_path: path to the root of the test resource folder contains file to be mapped
    @rv: (return code, stdout, stderr)
    """
    return util._exec(f"{mproect_path}/bin/mprotect_test", ["r", "w", f"{bin_path}/bin/hello"])

def mprotect_r_to_x(mproect_path, bin_path):
    """
    mprotect_r_to_x:
      Map a file/binary under @path with PROT_READ permissions,
      then change the permissions to PROT_EXEC.

    Returns the return code of mprotect and the output of helper binary

    @mprotect_path: path to the root of the test resource folder contains mprotect helper binary
    @bin_path: path to the root of the test resource folder contains file to be mapped
    @rv: (return code, stdout, stderr)
    """
    return util._exec(f"{mproect_path}/bin/mprotect_test", ["r", "x", f"{bin_path}/bin/hello"])

def mprotect_r_to_wx(mproect_path, bin_path):
    """
    mprotect_r_to_wx:
      Map a file/binary under @path with PROT_READ permissions,
      then change the permissions to PROT_EXEC and PROT_WRITE.

    Returns the return code of mprotect and the output of helper binary

    @mprotect_path: path to the root of the test resource folder contains mprotect helper binary
    @bin_path: path to the root of the test resource folder contains file to be mapped
    @rv: (return code, stdout, stderr)
    """
    return util._exec(f"{mproect_path}/bin/mprotect_test", ["r", "wx", f"{bin_path}/bin/hello"])