# Threat Model

IPE specifically targets the risk of tampering with user-space executable
code after the kernel has initially booted, including the kernel modules
loaded from userspace via ``modprobe`` or ``insmod``.

To illustrate, consider a scenario where an untrusted binary, possibly
malicious, is downloaded along with all necessary dependencies, including a
loader and libc. The primary function of IPE in this context is to prevent
the execution of such binaries and their dependencies.

IPE achieves this by verifying the integrity and authenticity of all
executable code before allowing them to run. It conducts a thorough
check to ensure that the code's integrity is intact and that they match an
authorized reference value (digest, signature, etc) as per the defined
policy. If a binary does not pass this verification process, either
because its integrity has been compromised or it does not meet the
authorization criteria, IPE will deny its execution. Additionally, IPE
generates audit logs which may be utilized to detect and analyze failures
resulting from policy violation.

Tampering threat scenarios include modification or replacement of
executable code by a range of actors including:

-  Actors with physical access to the hardware
-  Actors with local network access to the system
-  Actors with access to the deployment system
-  Compromised internal systems under external control
-  Malicious end users of the system
-  Compromised end users of the system
-  Remote (external) compromise of the system

IPE does not mitigate threats arising from malicious but authorized
developers (with access to a signing certificate), or compromised
developer tools used by them (i.e. return-oriented programming attacks).
Additionally, IPE draws hard security boundary between userspace and
kernelspace. As a result, IPE does not provide any protections against a
kernel level exploit, and a kernel-level exploit can disable or tamper
with IPE's protections.

The root of trust for all of IPE's verifications is the
`SYSTEM_TRUSTED_KEYRING` of the Linux kernel, which is a set of keys that
are provisioned at kernel build-time.
