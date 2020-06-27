# Integrity Policy Enforcement (IPE)

## Overview

IPE is a Linux Security Module, which allows for a configurable
policy to enforce integrity requirements on the whole system. It
attempts to solve the issue of code integrity: that any code being
executed (or files being read), are identical to the version that
was built by a trusted source. Simply stated, IPE helps the owner of a 
system ensure that only code they have authorized is allowed to execute.

There are multiple implementations already within the Linux kernel that
solve some measure of integrity verification. For instance, device-mapper
verity, which ensures integrity for a block device, and fs-verity which
is a system that ensures integrity for a filesystem. What these
implementations lack is a measure of run-time verification that binaries
are sourced from these locations. IPE aims to address this gap.

IPE is separated between two major components: A configurable policy,
provided by the LSM ("IPE Core"), and deterministic attributes provided by
the kernel to evaluate files against, ("IPE Properties").

## What is the value of code integrity?

Code integrity is identified as one of the most effective security mitigations
for modern systems. With Private Key Infrastructure and code signing you can 
effectively control the execution of all binaries on a system to be restricted to 
a known subset. This eliminates attacks such as:

1. Linker hijacking (LD_PRELOAD, LD_AUDIT, DLL Injection)
2. Binary rewriting
3. Malicious binary execution / loading

As a result, most of the low effort, high value attacks are mitigated completely.

## Use Cases

IPE is designed for use in devices with a specific purpose like embedded systems
(e.g. network firewall device in a data center), where all software
and configuration is built and provisioned by the owner.

Ideally, a system which leverages IPE is not intended for general
purpose computing and does not utilize any software or configuration
built by a third party. An ideal system to leverage IPE has both mutable
and immutable components, however, all binary executable code is immutable.

For the highest level of security, platform firmware should verify the
kernel and optionally the root filesystem (e.g. via U-Boot verified boot).
This allows the entire system to be integrity verified.

## Known Gaps

IPE cannot verify the integrity of anonymous executable memory, such as
the trampolines created by gcc closures and libffi, or JIT'd code.
Unfortunately, as this is dynamically generated code, there is no way for
IPE to detect that this code has not been tampered with in transition
from where it was built, to where it is running. As a result, IPE is
incapable of tackling this problem for dynamically generated code.

IPE cannot verify the integrity of interpreted languages' programs when
these scripts invoked via `<interpreter> <file>`. This is because the way
interpreters execute these files, the scripts themselves are not
evaluated as executable code through one of IPE's hooks. Interpreters
can be enlightened to the usage of IPE by trying to mmap a file into
executable memory (+X), after opening the file and responding to the
error code appropriately. This also applies to included files, or high
value files, such as configuration files of critical system components.
This specific gap is planned on being addressed within IPE.
