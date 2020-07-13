# FAQ

### What's the difference between other LSMs which provide integrity verification (i.e. IMA)?

IPE differs from other LSMs which provide integrity checking, as it has
no dependency on the filesystem metadata itself. The attributes that IPE
checks are deterministic properties that exist solely in the kernel.
Additionally, IPE provides no additional mechanisms of verifying these
files (e.g. IMA Signatures) - all of the attributes of verifying files are
existing features within the kernel.

Additionally, IPE is completely restricted to integrity. It offers no
measurement or attestation features, which IMA addresses.

### Where can I find the code for IPE?

The IPE LSM code has been submitted for review to the Linux kernel project
[here](https://lore.kernel.org/linux-integrity/?q=Integrity+Policy+Enforcement+LSM+%28IPE%29).
