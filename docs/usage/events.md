# Audit Events

IPE will emit a several forms of messages to the audit channel. This section
provides various information about these events and the descriptions of the
fields that are emitted by these events to help with analysis of audit logs.

## Policy Load / Staging

```auditd
AUDIT1808 IPE policy_name="AllowAll" policy_version=0.0.0 sha1=776FA5945C012EDDFC0866D7E3DE883CC0B67930
```

This event is emitted when a policy is loaded via `$SECURITYFS/ipe/new_policy`
or `$SECURITYFS/ipe/policies/<policy_name>/raw`. It is emitted to the audit
channel, and can be used to provide a record of what policies were loaded
on the system.

| Field		| Description	|
|:-------------:|:--------------|
| policy_name	| The `policy_name` field of the policy|
| policy_version| The `policy_version` triple _parsed_ from the policy<sup>1</sup>|
| sha1		| A SHA128 flat hash of the entire policy. Can be used to identify a policy.|

## Policy Activation / Enablement

```auditd
AUDIT1809 IPE policy_name="AllowAll" policy_version=0.0.0
```

This event is emitted when a policy is activated via `sysctl ipe.active_policy`
or when a policy is activated in place via
`$SECURITYFS/ipe/policies/<policy_name>/raw`. It is emitted to the audit
channel, and can be used to provide a record of when policies were made active.

| Field		| Description	|
|:-------------:|:--------------|
| policy_name	| The `policy_name` field of the policy|
| policy_version| The `policy_version` triple _parsed_ from the policy<sup>1</sup>|

## IPE Mode Switch

```auditd
AUDIT1811 IPE mode=enforce
AUDIT1811 IPE mode=permissive
```

This event is emitted when the IPE's mode of operation is changed through the `sysctl
ipe.enforce`. It is emitted to the audit channel, additionally, this event is emitted
early during system boot to the kernel channel (audit is not emitted) to identify
what mode IPE is started in.

| Field		| Description	|
|:-------------:|:--------------|
| mode	| The mode that IPE is set to. Can be either: `enforce` or `permissive`. See [the modes documentation for more information.](./index.md#modes) |

## IPE Binary Event

```auditd
AUDIT1810 IPE ctx_pid=297 ctx_op=EXECUTE ctx_hook=EXEC ctx_comm="sysctl" ctx_audit_pathname="/usr/lib/libc-2.30.so" ctx_ino=135442 ctx_dev=vda prop_boot_verified=TRUE prop_dmverity_roothash=NULL prop_dmverity_signature=FALSE rule="DEFAULT action=DENY"
```

This event is emitted when IPE evaluates a binary. By default<sup>2</sup>, 
it will only be triggered on "action=DENY" events, or "blocks". This event
provides a record of execution that violated policy and can be used to identify
gaps within the currently deployed policy, or a system that may be
under attack. Certain fields may be omitted, or replaced with `ERR(%d)`
which identifes the error code when attempting to retrieve that value.

| Field				| Description	| Optional	|
|:-----------------------------:|:--------------|:-------------:|
|`ctx_pid`|The [process ID](https://en.wikipedia.org/wiki/Process_identifier) of the process being evaluated.|No|
|`ctx_op`|The operation that IPE is evaluating the file under. See [op](properties.md#op).|No|
|`ctx_hook`|The LSM hook that the file is being evaluated under. Provides a more granular description that `ctx_op`.|	No	|
|`ctx_comm`|The effective name of the process, as evaluated by the kernel.|	No	|
|`ctx_audit_pathname`|The effective absolute path to the file being evaluated. Walks past chroots and mount points.|	Yes	|
|`ctx_ino`|The inode number of the file being evaluated.|	Yes	|
|`ctx_dev`|The device name that the file belongs to.|	Yes	|
|`prop_boot_verified`|The evaluation of the property, `boot_verified`. Can be ommitted if this property is not present in the kernel (not compiled in).|	Yes	|
|`prop_dmverity_roothash`|The evaluation of the property, `dmverity_roothash`. Can be ommitted if this property is not present in the kernel (not compiled in).|	Yes	|
|`prop_dmverity_signature`|The evaluation of the property, `dmverity_signature`. Can be ommitted if this property is not present in the kernel (not compiled in).|	Yes	|
|`rule`|The plain-text approximation of the rule that was matched.|	No	|


---

<sup>1</sup> A policy with 4+ version numbers will parse successfully, but
only the first three will be considered as part of the version. These fields
will only emit the parsed version.


<sup>2</sup> IPE supports success auditing. When enabled, all events that pass IPE 
policy and are not blocked will emit an audit event. This is disabled by 
default, and can be enabled via the kernel command line
`ipe.success_audit=(0|1)` or the sysctl `ipe.success_audit=(0|1)`.

This is very noisy, as IPE will check every user-mode binary on the system,
but is useful for debugging policies.
