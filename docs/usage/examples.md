# Policy Examples

## Allow all

```
policy_name=Allow_All policy_version=0.0.0
DEFAULT action=ALLOW
```

## Allow only initramfs

```
policy_name=Allow_All_Initramfs policy_version=0.0.0
DEFAULT action=DENY

op=EXECUTE boot_verified=TRUE action=ALLOW
```

## Allow any signed dm-verity volume and the initramfs

```
policy_name=AllowSignedAndInitramfs policy_version=0.0.0
DEFAULT action=DENY

op=EXECUTE boot_verified=TRUE action=ALLOW
op=EXECUTE dmverity_signature=TRUE action=ALLOW
```

## Prohibit execution from a specific dm-verity volume

```
policy_name=AllowSignedAndInitramfs policy_version=0.0.0
DEFAULT action=DENY

op=EXECUTE dmverity_roothash=sha256:cd2c5bae7c6c579edaae4353049d58eb5f2e8be0244bf05345bc8e5ed257baff action=DENY

op=EXECUTE boot_verified=TRUE action=ALLOW
op=EXECUTE dmverity_signature=TRUE action=ALLOW
```

## Allow only a specific dm-verity volume

```
policy_name=AllowSignedAndInitramfs policy_version=0.0.0
DEFAULT action=DENY

op=EXECUTE dmverity_roothash=sha256:401fcec5944823ae12f62726e8184407a5fa9599783f030dec146938 action=ALLOW
```

## Allow any signed fs-verity file

```
policy_name=AllowSignedFSVerity policy_version=0.0.0
DEFAULT action=DENY

op=EXECUTE fsverity_signature=TRUE action=ALLOW
```

## Prohibit execution of a specific fs-verity file

```
policy_name=ProhibitSpecificFSVF policy_version=0.0.0
DEFAULT action=DENY

op=EXECUTE fsverity_digest=sha256:fd88f2b8824e197f850bf4c5109bea5cf0ee38104f710843bb72da796ba5af9e action=DENY
op=EXECUTE boot_verified=TRUE action=ALLOW
op=EXECUTE dmverity_signature=TRUE action=ALLOW
```
