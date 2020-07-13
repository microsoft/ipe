# Policy Examples

## Allow all

```
policy_name="Allow All" policy_version=0.0.0
DEFAULT action=ALLOW
```

## Allow only initial superblock

```
policy_name="Allow All Initial SB" policy_version=0.0.0
DEFAULT action=DENY

op=EXECUTE boot_verified=TRUE action=ALLOW
```

## Allow any signed dm-verity volume and the initial superblock

```
policy_name="AllowSignedAndInitial" policy_version=0.0.0
DEFAULT action=DENY

op=EXECUTE boot_verified=TRUE action=ALLOW
op=EXECUTE dmverity_signature=TRUE action=ALLOW
```

## Prohibit execution from a specific dm-verity volume

```
policy_name="AllowSignedAndInitial" policy_version=0.0.0
DEFAULT action=DENY

op=EXECUTE dmverity_roothash=401fcec5944823ae12f62726e8184407a5fa9599783f030dec146938 action=DENY
op=EXECUTE boot_verified=TRUE action=ALLOW
op=EXECUTE dmverity_signature=TRUE action=ALLOW
```

## Allow only a specific dm-verity volume

```
policy_name="AllowSignedAndInitial" policy_version=0.0.0
DEFAULT action=DENY

op=EXECUTE dmverity_roothash=401fcec5944823ae12f62726e8184407a5fa9599783f030dec146938 action=ALLOW
```