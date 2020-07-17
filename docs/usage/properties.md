# IPE Properties

IPE properties are `key=value` pairs expressed in IPE policy.
These properties can be used in rules within IPE policy to control
the evaluation of binaries and files on the system IPE is protecting.

This page contains a listing of all currently supported properties within
IPE, and a description of the available values for each property.

Usermode can interrogate the kernel via `/sys/kernel/security/ipe/property_config`
which, when read, will return a string of form:

```
Property1=Version1
Property2=Version2
.
.
.
PropertyN=VersionN
```

For all properties that IPE is configured to understand.

## op

### Version 1

Indicates the operation for a rule to apply to. Must be in every rule. IPE
supports the following operations:

`EXECUTE`
> Pertains to any file attempting to be executed, or loaded as an executable.

`FIRMWARE`:
> Pertains to firmware being loaded via the firmware_class interface. This
> covers both the preallocated buffer and the firmware file itself.

`KMODULE`:
> Pertains to loading kernel modules via `modprobe` or `insmod`.

`KEXEC_IMAGE`:
> Pertains to kernel images loading via `kexec`.

`KEXEC_INITRAMFS`
> Pertains to initrd images loading via `kexec --initrd`.

`POLICY`:
> Controls loading IMA policies through the `/sys/kernel/security/ima/policy`
> securityfs entry.

`X509_CERT`:
> Controls loading IMA certificates through the Kconfigs, `CONFIG_IMA_X509_PATH`
> and `CONFIG_EVM_X509_PATH`.

`KERNEL_READ`:
> Short-hand for the following operations: `FIRMWARE`, `KMODULE`,
> `KEXEC_IMAGE`, `KEXEC_INITRAMFS`, `POLICY`, and `X509_CERTIFICATE`

## action

### Version 1

Determines what IPE should do when a rule matches. Must be in every rule. Can be one of:

`ALLOW`:
> If the rule matches, explicitly allow the call to proceed without executing any more rules.

`DENY`:
> If the rule matches, explicitly prohibit the call from proceeding without
executing any more rules.


## boot_verified

### Version 1

This property can be utilized for authorization of the first
super-block that is mounted on the system, where IPE attempts
to evaluate a file. Typically this is used for systems with
an initramfs or other initial disk, where this is unmounted before
the system becomes available, and is not covered by any other property.
This property is enabled by the Kconfig, `CONFIG_IPE_BOOT_PROP`.
The format of this property is:

```
    boot_verified=(TRUE|FALSE)
```

> WARNING: This property will trust any disk where the first IPE
> evaluation occurs. If you do not have a startup disk that is
> unpacked and unmounted (like initramfs), then it will automatically
> trust the root filesystem and potentially overauthorize the entire
> disk.

## dmverity_roothash

### Version 1

This property can be utilized for authorization or revocation of
specific dm-verity volumes, identified via root hash. It has a
dependency on the DM_VERITY module. This property is enabled by
the property: `CONFIG_IPE_DM_VERITY_ROOTHASH`. The format of this
property is:

```
dmverity_roothash=HashHexDigest
```

## dmverity_signature

### Version 1

This property can be utilized for authorization of all dm-verity
volumes that have a signed roothash that chains to the system
trusted keyring. It has a dependency on the
`DM_VERITY_VERIFY_ROOTHASH_SIG` Kconfig. This property is enabled by
the Kconfig: `CONFIG_IPE_DM_VERITY_SIGNATURE`.
The format of this property is:

```
dmverity_signature=(TRUE|FALSE)
```
