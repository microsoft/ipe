# Audit Events

## 1420 AUDIT_IPE_ACCESS

Event Examples:

```
type=1420 audit(1653364370.067:61): ipe_op=EXECUTE ipe_hook=MMAP enforcing=1 pid=2241 comm="ld-linux.so" path="/deny/lib/libc.so.6" dev="sda2" ino=14549020 rule="DEFAULT action=DENY"
type=1300 audit(1653364370.067:61): SYSCALL arch=c000003e syscall=9 success=no exit=-13 a0=7f1105a28000 a1=195000 a2=5 a3=812 items=0 ppid=2219 pid=2241 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=2 comm="ld-linux.so" exe="/tmp/ipe-test/lib/ld-linux.so" subj=unconfined key=(null)
type=1327 audit(1653364370.067:61): 707974686F6E3300746573742F6D61696E2E7079002D6E00

type=1420 audit(1653364735.161:64): ipe_op=EXECUTE ipe_hook=MMAP enforcing=1 pid=2472 comm="mmap_test" path=? dev=? ino=? rule="DEFAULT action=DENY"
type=1300 audit(1653364735.161:64): SYSCALL arch=c000003e syscall=9 success=no exit=-13 a0=0 a1=1000 a2=4 a3=21 items=0 ppid=2219 pid=2472 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=2 comm="mmap_test" exe="/root/overlake_test/upstream_test/vol_fsverity/bin/mmap_test" subj=unconfined key=(null)
type=1327 audit(1653364735.161:64): 707974686F6E3300746573742F6D61696E2E7079002D6E00
```

This event indicates that IPE made an access control decision; the IPE specific record (1420) is always emitted in conjunction with a `AUDITSYSCALL` record.

Determining whether IPE is in permissive or enforced mode can be derived from `success` property and exit code of the `AUDITSYSCALL` record.

Field descriptions:

| Field      | Value Type | Optional? | Description of Value                                                            |
|------------|------------|-----------|---------------------------------------------------------------------------------|
| ipe_op     | string     | No        | The IPE operation name associated with the log                                  |
| ipe_hook   | string     | No        | The name of the LSM hook that triggered the IPE event                           |
| enforcing  | integer    | No        | The current IPE enforcing state 1 is in enforcing mode, 0 is in permissive mode |
| pid        | integer    | No        | The pid of the process that triggered the IPE event.                            |
| comm       | string     | No        | The command line program name of the process that triggered the IPE event       |
| path       | string     | Yes       | The absolute path to the evaluated file                                         |
| ino        | integer    | Yes       | The inode number of the evaluated file                                          |
| dev        | string     | Yes       | The device name of the evaluated file, e.g. vda                                 |
| rule       | string     | No        | The matched policy rule                                                         |

## 1421 AUDIT_IPE_CONFIG_CHANGE

Event Example:

```
type=1421 audit(1653425583.136:54): old_active_pol_name="Allow_All" old_active_pol_version=0.0.0 old_policy_digest=sha256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 new_active_pol_name="boot_verified" new_active_pol_version=0.0.0 new_policy_digest=sha256:820EEA5B40CA42B51F68962354BA083122A20BB846F26765076DD8EED7B8F4DB auid=4294967295 ses=4294967295 lsm=ipe res=1
type=1300 audit(1653425583.136:54): SYSCALL arch=c000003e syscall=1 success=yes exit=2 a0=3 a1=5596fcae1fb0 a2=2 a3=2 items=0 ppid=184 pid=229 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=4294967295 comm="python3" exe="/usr/bin/python3.10" key=(null)
type=1327 audit(1653425583.136:54): PROCTITLE proctitle=707974686F6E3300746573742F6D61696E2E7079002D66002E2
```

This event indicates that IPE switched the active policy from one to another along with the version and the hash digest of the two policies.
Note IPE can only have one policy active at a time, all access decision evaluation is based on the current active policy.
The normal procedure to deploy a new policy is loading the policy to deploy into the kernel first, then switch the active policy to it.

This record will always be emitted in conjunction with a `AUDITSYSCALL` record for the `write` syscall.

Field descriptions:

| Field                  | Value Type | Optional? | Description of Value                              |
|------------------------|------------|-----------|---------------------------------------------------|
| old_active_pol_name    | string     | No        | The name of previous active policy                |
| old_active_pol_version | string     | No        | The version of previous active policy             |
| old_policy_digest      | string     | No        | The hash of previous active policy                |
| new_active_pol_name    | string     | No        | The name of current active policy                 |
| new_active_pol_version | string     | No        | The version of current active policy              |
| new_policy_digest      | string     | No        | The hash of current active policy                 |
| auid                   | integer    | No        | The login user ID                                 |
| ses                    | integer    | No        | The login session ID                              |
| lsm                    | string     | No        | The LSM name associated with the event            |
| res                    | integer    | No        | The result of the audited operation(success/fail) |

## 1422 AUDIT_IPE_POLICY_LOAD

Event Example:

```
type=1422 audit(1653425529.927:53): policy_name="boot_verified" policy_version=0.0.0 policy_digest=sha256:820EEA5B40CA42B51F68962354BA083122A20BB846F26765076DD8EED7B8F4DB auid=4294967295 ses=4294967295 lsm=ipe res=1
type=1300 audit(1653425529.927:53): arch=c000003e syscall=1 success=yes exit=2567 a0=3 a1=5596fcae1fb0 a2=a07 a3=2 items=0 ppid=184 pid=229 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=4294967295 comm="python3" exe="/usr/bin/python3.10" key=(null)
type=1327 audit(1653425529.927:53): PROCTITLE proctitle=707974686F6E3300746573742F6D61696E2E7079002D66002E2E
```

This record indicates a new policy has been loaded into the kernel with the policy name, policy version and policy hash.

This record will always be emitted in conjunction with a `AUDITSYSCALL` record for the `write` syscall.

Field descriptions:

| Field          | Value Type | Optional? | Description of Value                              |
|----------------|------------|-----------|---------------------------------------------------|
| policy_name    | string     | No        | The policy_name                                   |
| policy_version | string     | No        | The policy_version                                |
| policy_digest  | string     | No        | The policy hash                                   |
| auid           | integer    | No        | The login user ID                                 |
| ses            | integer    | No        | The login session ID                              |
| lsm            | string     | No        | The LSM name associated with the event            |
| res            | integer    | No        | The result of the audited operation(success/fail) |

## 1404 AUDIT_MAC_STATUS

Event Examples:

```
type=1404 audit(1653425689.008:55): enforcing=0 old_enforcing=1 auid=4294967295 ses=4294967295 enabled=1 old-enabled=1 lsm=ipe res=1
type=1300 audit(1653425689.008:55): arch=c000003e syscall=1 success=yes exit=2 a0=1 a1=55c1065e5c60 a2=2 a3=0 items=0 ppid=405 pid=441 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=)
type=1327 audit(1653425689.008:55): proctitle="-bash"

type=1404 audit(1653425689.008:55): enforcing=1 old_enforcing=0 auid=4294967295 ses=4294967295 enabled=1 old-enabled=1 lsm=ipe res=1
type=1300 audit(1653425689.008:55): arch=c000003e syscall=1 success=yes exit=2 a0=1 a1=55c1065e5c60 a2=2 a3=0 items=0 ppid=405 pid=441 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=)
type=1327 audit(1653425689.008:55): proctitle="-bash"
```

This record will always be emitted in conjunction with a `AUDITSYSCALL` record for the `write` syscall.

Field descriptions:

| Field         | Value Type | Optional? | Description of Value                                                                            |
|---------------|------------|-----------|-------------------------------------------------------------------------------------------------|
| enforcing     | integer    | No        | The enforcing state IPE is being switched to, 1 is in enforcing mode, 0 is in permissive mode   |
| old_enforcing | integer    | No        | The enforcing state IPE is being switched from, 1 is in enforcing mode, 0 is in permissive mode |
| auid          | integer    | No        | The login user ID                                                                               |
| ses           | integer    | No        | The login session ID                                                                            |
| enabled       | integer    | No        | The new TTY audit enabled setting                                                               |
| old-enabled   | integer    | No        | The old TTY audit enabled setting                                                               |
| lsm           | string     | No        | The LSM name associated with the event                                                          |
| res           | integer    | No        | The result of the audited operation (success/fail)                                              |

## Success Auditing

IPE supports success auditing. When enabled, all events that pass IPE policy and are not blocked will emit an audit event. This is disabled by default, and can be enabled via the kernel command line `ipe.success_audit=(0|1)` or `/sys/kernel/security/ipe/success_audit` securityfs file.

This is *very* noisy, as IPE will check every userspace binary on the system, but is useful for debugging policies.

**NOTE:**

If a traditional MAC system is enabled (SELinux, apparmor, smack, etcetera), all writes to ipe's securityfs nodes require `CAP_MAC_ADMIN`.
