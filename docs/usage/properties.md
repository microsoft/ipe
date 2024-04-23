# IPE Properties

IPE properties are `key=value` pairs expressed in IPE
policy. Two properties are built into the policy parser: 'op' and 'action'.
The other properties are used to restrict immutable security properties
about the files being evaluated. Currently those properties are:
`boot_verified`, `dmverity_signature`, `dmverity_roothash`,
`fsverity_signature`, `fsverity_digest`. A description of all
properties supported by IPE are listed below:

## op

Indicates the operation for a rule to apply to. Must be in every rule,
as the first token. IPE supports the following operations:

- **EXECUTE**
  - Pertains to any file attempting to be executed, or loaded as an
    executable.

- **FIRMWARE**:
  - Pertains to firmware being loaded via the firmware_class interface.
    This covers both the preallocated buffer and the firmware file
    itself.

- **KMODULE**:
  - Pertains to loading kernel modules via `modprobe` or `insmod`.

- **KEXEC_IMAGE**:
  - Pertains to kernel images loading via `kexec`.

- **KEXEC_INITRAMFS**
  - Pertains to initrd images loading via `kexec --initrd`.

- **POLICY**:
  - Controls loading policies via reading a kernel-space initiated read.
    An example of such is loading IMA policies by writing the path
    to the policy file to `$securityfs/ima/policy`.

- **X509_CERT**:
  - Controls loading IMA certificates through the Kconfigs,
    `CONFIG_IMA_X509_PATH` and `CONFIG_EVM_X509_PATH`.

## action

Determines what IPE should do when a rule matches. Must be in every
rule, as the final clause. Can be one of:

- **ALLOW**:
  - If the rule matches, explicitly allow access to the resource to proceed
    without executing any more rules.

- **DENY**:
  - If the rule matches, explicitly prohibit access to the resource to
    proceed without executing any more rules.

## boot_verified

This property can be utilized for authorization of files from initramfs.
The format of this property is:

    boot_verified=(TRUE|FALSE)

**WARNING:**

This property will trust files from initramfs(rootfs). It should
only be used during the early booting stage. Before mounting the real
rootfs on top of the initramfs, initramfs script will recursively
remove all files and directories on the initramfs. This is typically
implemented by using switch_root(8). Therefore the initramfs will be empty and not accessible after the real
rootfs takes over. It is advised to switch to a different policy
that doesn't rely on the property after this point.
This ensures that the trust policies remain relevant and effective
throughout the system's operation.

## dmverity_roothash

This property can be utilized for authorization or revocation of
specific dm-verity volumes, identified via its root hash. It has a
dependency on the DM_VERITY module. This property is controlled by
the `IPE_PROP_DM_VERITY` config option, it will be automatically
selected when `IPE_SECURITY`, `DM_VERITY` and
`DM_VERITY_VERIFY_ROOTHASH_SIG` are all enabled.
The format of this property is:

    dmverity_roothash=DigestName:HexadecimalString

The supported DigestNames for dmverity_roothash are:

- blake2b-512
- blake2s-256
- sha1
- sha256
- sha384
- sha512
- sha3-224
- sha3-256
- sha3-384
- sha3-512
- md4
- md5
- sm3
- rmd160

## dmverity_signature

This property can be utilized for authorization of all dm-verity
volumes that have a signed roothash that validated by a keyring
specified by dm-verity's configuration, either the system trusted
keyring, or the secondary keyring. It depends on
`DM_VERITY_VERIFY_ROOTHASH_SIG` config option and is controlled by
the `IPE_PROP_DM_VERITY` config option, it will be automatically
selected when `IPE_SECURITY`, `DM_VERITY` and
`DM_VERITY_VERIFY_ROOTHASH_SIG` are all enabled.
The format of this property is:

    dmverity_signature=(TRUE|FALSE)

## fsverity_digest

This property can be utilized for authorization or revocation of
specific fsverity enabled file, identified via its fsverity digest.
It depends on `FS_VERITY` config option and is controlled by
`CONFIG_IPE_PROP_FS_VERITY`. The format of this property is:

    fsverity_digest=DigestName:HexadecimalString

The supported DigestNames for fsverity_roothash are:

- sha256
- sha512

## fsverity_signature

This property is used to authorize all fs-verity enabled files that have
been verified by fs-verity's built-in signature mechanism. The signature
verification relies on a key stored within the ".fs-verity" keyring. It
depends on `CONFIG_FS_VERITY_BUILTIN_SIGNATURES` and it is controlled by
the Kconfig `CONFIG_IPE_PROP_FS_VERITY`. The format of this
property is:

    fsverity_signature=(TRUE|FALSE)
