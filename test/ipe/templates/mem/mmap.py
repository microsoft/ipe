#
# Integrity Policy Enforcement Test Suite
# Copyright (C), Microsoft Corporation, All Rights Reserved.
#
import ipe.util as util

def mmap_r(mmap_path, bin_path):
    """
    mmap_r:
      Map a file/binary under @bin_path with PROT_READ permissions.

    Returns the return code of mmap and the output of helper binary

    @mmap_path: path to the root of the test resource folder contains mmap helper binary
    @bin_path: path to the root of the test resource folder contains file to be mapped
    @rv: (return code, stdout, stderr)
    """
    return util._exec(f"{mmap_path}/bin/mmap_test", ["r", f"{bin_path}/bin/hello"])


def mmap_w(mmap_path, bin_path):
    """
    mmap_w:
      Map a file/binary under @bin_path with PROT_WRITE permissions.

    Returns the return code of mmap and the output of helper binary

    @mmap_path: path to the root of the test resource folder contains mmap helper binary
    @bin_path: path to the root of the test resource folder contains file to be mapped
    @rv: (return code, stdout, stderr)
    """
    return util._exec(f"{mmap_path}/bin/mmap_test", ["w", f"{bin_path}/bin/hello"])


def mmap_x(mmap_path, bin_path):
    """
    mmap_x:
      Map a file/binary under @bin_path with PROT_EXEC permissions.

    Returns the return code of mmap and the output of helper binary

    @mmap_path: path to the root of the test resource folder contains mmap helper binary
    @bin_path: path to the root of the test resource folder contains file to be mapped
    @rv: (return code, stdout, stderr)
    """
    return util._exec(f"{mmap_path}/bin/mmap_test", ["x", f"{bin_path}/bin/hello"])


def mmap_rw(mmap_path, bin_path):
    """
    mmap_rw:
      Map a file/binary under @bin_path with PROT_READ and PROT_WRITE permissions.

    Returns the return code of mmap and the output of helper binary

    @mmap_path: path to the root of the test resource folder contains mmap helper binary
    @bin_path: path to the root of the test resource folder contains file to be mapped
    @rv: (return code, stdout, stderr)
    """
    return util._exec(f"{mmap_path}/bin/mmap_test", ["rw", f"{bin_path}/bin/hello"])


def mmap_rx(mmap_path, bin_path):
    """
    mmap_rx:
      Map a file/binary under @bin_path with PROT_READ and PROT_EXEC permissions.

    Returns the return code of mmap and the output of helper binary

    @mmap_path: path to the root of the test resource folder contains mmap helper binary
    @bin_path: path to the root of the test resource folder contains file to be mapped
    @rv: (return code, stdout, stderr)
    """
    return util._exec(f"{mmap_path}/bin/mmap_test", ["rx", f"{bin_path}/bin/hello"])


def mmap_wx(mmap_path, bin_path):
    """
    mmap_wx:
      Map a file/binary under @path with PROT_WRITE and PROT_EXEC permissions.

    Returns the return code of mmap and the output of helper binary

    @mmap_path: path to the root of the test resource folder contains mmap helper binary
    @bin_path: path to the root of the test resource folder contains file to be mapped
    @rv: (return code, stdout, stderr)
    """
    return util._exec(f"{mmap_path}/bin/mmap_test", ["wx", f"{bin_path}/bin/hello"])


def mmap_r_anon(path):
    """
    mmap_r_anon:
      Map a region of anonymous memory with PROT_READ permissions.

    Returns the return code of mmap and the output of helper binary

    @path: path to the root of the test resource folder contains mmap helper binary
    @rv: (return code, stdout, stderr)
    """
    return util._exec(f"{path}/bin/mmap_test", ["r"])


def mmap_w_anon(path):
    """
    mmap_w_anon:
      Map a region of anonymous memory with PROT_WRITE permissions.

    Returns the return code of mmap and the output of helper binary

    @path: path to the root of the test resource folder contains mmap helper binary
    @rv: (return code, stdout, stderr)
    """
    return util._exec(f"{path}/bin/mmap_test", ["w"])


def mmap_x_anon(path):
    """
    mmap_x_anon:
      Map a region of anonymous memory with PROT_EXEC permissions.

    Returns the return code of mmap and the output of helper binary

    @path: path to the root of the test resource folder contains mmap helper binary
    @rv: (return code, stdout, stderr)
    """
    return util._exec(f"{path}/bin/mmap_test", ["x"])


def mmap_rw_anon(path):
    """
    mmap_rw_anon:
      Map a region of anonymous memory with PROT_READ | PROT_WRITE
      permissions.

    Returns the return code of mmap and the output of helper binary

    @path: path to the root of the test resource folder contains mmap helper binary
    @rv: (return code, stdout, stderr)
    """
    return util._exec(f"{path}/bin/mmap_test", ["rw"])


def mmap_rx_anon(path):
    """
    mmap_rx_anon:
      Map a region of anonymous memory with PROT_READ | PROT_EXEC
      permissions.

    Returns the return code of mmap and the output of helper binary

    @path: path to the root of the test resource folder contains mmap helper binary
    @rv: (return code, stdout, stderr)
    """
    return util._exec(f"{path}/bin/mmap_test", ["rx"])


def mmap_wx_anon(path):
    """
    mmap_wx_anon:
      Map a region of anonymous memory with PROT_WRITE | PROT_EXEC
      permissions.

    Returns the return code of mmap and the output of helper binary

    @path: path to the root of the test resource folder contains mmap helper binary
    @rv: (return code, stdout, stderr)
    """
    return util._exec(f"{path}/bin/mmap_test", ["wx"])


def mmap_r_shared(mmap_path, bin_path):
    """
    mmap_r_shared:
      Map a region of shared memory with PROT_READ
      permissions.

    Returns the return code of mmap and the output of helper binary

    @path: path to the root of the test resource folder contains mmap helper binary
    @rv: (return code, stdout, stderr)
    """
    return util._exec(f"{mmap_path}/bin/mmap_test", ["rs", f"{bin_path}/bin/hello"])


def mmap_x_shared(mmap_path, bin_path):
    """
    mmap_x_shared:
      Map a region of shared memory with PROT_EXEC
      permissions.

    Returns the return code of mmap and the output of helper binary

    @path: path to the root of the test resource folder contains mmap helper binary
    @rv: (return code, stdout, stderr)
    """
    return util._exec(f"{mmap_path}/bin/mmap_test", ["xs", f"{bin_path}/bin/hello"])


def mmap_rx_shared(mmap_path, bin_path):
    """
    mmap_rx_shared:
      Map a region of shared memory with PROT_EXEC and
      PROT_READ permissions.

    Returns the return code of mmap and the output of helper binary

    @path: path to the root of the test resource folder contains mmap helper binary
    @rv: (return code, stdout, stderr)
    """
    return util._exec(f"{mmap_path}/bin/mmap_test", ["rxs", f"{bin_path}/bin/hello"])


def mmap_r_shared_anon(path):
    """
    mmap_r_shared:
      Map a region of shared, anonymous memory with PROT_READ
      permissions.

    Returns the return code of mmap and the output of helper binary

    @path: path to the root of the test resource folder contains mmap helper binary
    @rv: (return code, stdout, stderr)
    """
    return util._exec(f"{path}/bin/mmap_test", ["rs"])


def mmap_x_shared_anon(path):
    """
    mmap_x_shared:
      Map a region of shared, anonymous memory with PROT_EXEC
      permissions.

    Returns the return code of mmap and the output of helper binary

    @path: path to the root of the test resource folder contains mmap helper binary
    @rv: (return code, stdout, stderr)
    """
    return util._exec(f"{path}/bin/mmap_test", ["xs"])


def mmap_rx_shared_anon(path):
    """
    mmap_rx_shared:
      Map a region of shared, anonymous memory with PROT_EXEC and
      PROT_READ permissions.

    Returns the return code of mmap and the output of helper binary

    @path: path to the root of the test resource folder contains mmap helper binary
    @rv: (return code, stdout, stderr)
    """
    return util._exec(f"{path}/bin/mmap_test", ["rxs"])
