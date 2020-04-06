# Threat Model

The threat type addressed by IPE is tampering of executable user-land code
beyond the initially booted kernel, and the initial verification of kernel
modules that are loaded in userland through `modprobe` or `insmod`.

Tampering violates the property of integrity. IPE's role in mitigating this
threat is to verify the integrity (and authenticity) of all executable code
and to deny their use if integrity verification fails. IPE generates audit
logs which may be utilized to detect integrity verification failures.

Tampering threat scenarios include modification or replacement of executable
code by a range of actors including:

+ Insiders with physical access to the hardware
+ Insiders with local network access to the system
+ Insiders with access to the deployment system
+ Compromised internal systems under external control
+ Malicious end users of the system
+ Compromised end users of the system
+ Remote (external) compromise of the system

IPE does not mitigate threats arising from malicious authorized
developers, or compromised developer tools used by authorized developers.
Additionally, IPE draws hard security boundary between user mode and
kernel mode. As a result, IPE does not provide any protections against a
kernel level exploit, and a kernel-level exploit can disable or tamper with
IPE's protections.

The root of trust for all of IPE's verifications is the
`SYSTEM_TRUSTED_KEYRING` of the Linux kernel, which is a set of keys that
are provisioned at kernel build-time.