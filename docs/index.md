# Integrity Policy Enforcement (IPE)

## Overview

Integrity Policy Enforcement (IPE) is a Linux Security Module that takes a
complementary approach to access control. Unlike traditional access control
mechanisms that rely on labels and paths for decision-making, IPE focuses
on the immutable security properties inherent to system components. These
properties are fundamental attributes or features of a system component
that cannot be altered, ensuring a consistent and reliable basis for
security decisions.

To elaborate, in the context of IPE, system components primarily refer to
files or the devices these files reside on. However, this is just a
starting point. The concept of system components is flexible and can be
extended to include new elements as the system evolves. The immutable
properties include the origin of a file, which remains constant and
unchangeable over time. For example, IPE policies can be crafted to trust
files originating from the initramfs. Since initramfs is typically verified
by the bootloader, its files are deemed trustworthy; "file is from
initramfs" becomes an immutable property under IPE's consideration.

The immutable property concept extends to the security features enabled on
a file's origin, such as dm-verity or fs-verity, which provide a layer of
integrity and trust. For example, IPE allows the definition of policies
that trust files from a dm-verity protected device. dm-verity ensures the
integrity of an entire device by providing a verifiable and immutable state
of its contents. Similarly, fs-verity offers filesystem-level integrity
checks, allowing IPE to enforce policies that trust files protected by
fs-verity. These two features cannot be turned off once established, so
they are considered immutable properties. These examples demonstrate how
IPE leverages immutable properties, such as a file's origin and its
integrity protection mechanisms, to make access control decisions.

For the IPE policy, specifically, it grants the ability to enforce
stringent access controls by assessing security properties against
reference values defined within the policy. This assessment can be based on
the existence of a security property (e.g., verifying if a file originates
from initramfs) or evaluating the internal state of an immutable security
property. The latter includes checking the roothash of a dm-verity
protected device, determining whether dm-verity possesses a valid
signature, assessing the digest of a fs-verity protected file, or
determining whether fs-verity possesses a valid built-in signature. This
nuanced approach to policy enforcement enables a highly secure and
customizable system defense mechanism, tailored to specific security
requirements and trust models.

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

IPE works best in fixed-function devices: Devices in which their purpose
is clearly defined and not supposed to be changed (e.g. network firewall
device in a data center, an IoT device, etcetera), where all software and
configuration is built and provisioned by the system owner.

IPE is a long-way off for use in general-purpose computing: the Linux
community as a whole tends to follow a decentralized trust model,
known as the web of trust, which IPE has no support for as of  yet.
There are exceptions, such as the case where a Linux distribution
vendor trusts only their own keys, where IPE can successfully be used
to enforce the trust requirement.

Additionally, while most packages are signed today, the files inside
the packages (for instance, the executables), tend to be unsigned. This
makes it difficult to utilize IPE in systems where a package manager is
expected to be functional, without major changes to the package manager
and ecosystem behind it.

## Known Gaps

1. IPE cannot verify the integrity of anonymous executable memory, such as
  the trampolines created by gcc closures and libffi (<3.4.2), or JIT'd code.
  Unfortunately, as this is dynamically generated code, there is no way
  for IPE to ensure the integrity of this code to form a trust basis. In all
  cases, the return result for these operations will be whatever the admin
  configures the DEFAULT action for "EXECUTE".

2. IPE cannot verify the integrity of interpreted languages' programs when
  these scripts invoked via ``<interpreter> <file>``. This is because the
  way interpreters execute these files, the scripts themselves are not
  evaluated as executable code through one of IPE's hooks. Interpreters
  can be enlightened to the usage of IPE by trying to mmap a file into
  executable memory (+X), after opening the file and responding to the
  error code appropriately. This also applies to included files, or high
  value files, such as configuration files of critical system components.
