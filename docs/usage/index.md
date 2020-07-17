# IPE Policy

The most essential part of IPE is its customizable policy which allows users 
to specify the rules that the LSM should enforce for different operations. 
This policy is designed to be both forward compatible and backwards compatible.
There is one required line, at the top of the policy, indicating the
policy name, and the policy version, for instance:

```
policy_name="Ex Policy" policy_version=0.0.0
```

The policy name is a unique key identifying this policy in a human readable
name. This is used to create nodes under securityfs as well as uniquely
identify policies to deploy new policies vs update existing policies.

The policy version indicates the current version of the policy (NOT the
policy syntax version). This is used to prevent roll-back of policy to
potentially insecure previous versions of the policy.

The next portion of IPE policy, are rules. Rules are formed by key=value
pairs, known as properties. IPE rules require two properties: "action",
which determines what IPE does when it encounters a match against the
rule, and "op", which determines when that rule should be evaluated.
Thus, a minimal rule is:

```
op=EXECUTE action=ALLOW
```

This example will allow any execution. Additional properties are used to
restrict attributes about the files being evaluated. These properties are
intended to be deterministic attributes that are resident in the kernel.

Order does not matter for the rule's properties - they can be listed in
any order, however it is encouraged to have the "op" property be first,
and the "action" property be last for readability. Rules are evaluated
top-to-bottom. As a result, any revocation rules, or denies should be
placed early in the file to ensure that these rules are evaluated before as
rule with "action=ALLOW" is hit.

Any unrecognized syntax in the policy will result in a fatal error to
parse the policy. IPE policy supports comments. The character '#' will
function as a  comment, ignoring all characters to the right of '#'
until the newline.

The default behavior of IPE evaluations can also be expressed in policy,
through the `DEFAULT` statement. This can be done at a global level, or
a per-operation level:

```
# Global
DEFAULT action=ALLOW

# Operation Specific
DEFAULT op=EXECUTE action=ALLOW
```

A DEFAULT operation must be set for all understood
operations within IPE. For policies to remain completely forwards
compatible, it is recommended that users add a `DEFAULT action=ALLOW`
and override the defaults on a per-operation basis.

## Early user-mode protection

With configurable policy-based LSMs, there's several issues with enforcing
the configurable policies at startup, around reading and parsing the policy:

1. The kernel _should_ not read files from userland, so directly reading
the policy file is prohibited.
2. The kernel command line has a character limit, and one kernel module
should not reserve the entire character limit for its own configuration.
3. There are various boot loaders in the kernel ecosystem, so handing off
a memory block would be costly to maintain.

As a result, IPE has addressed this problem through a concept of a "boot
policy". A boot policy is a minimal policy, compiled into the kernel. This
policy is intended to get the system to a state where userland is setup
and ready to receive commands, at which point a more complex policy ("user policies")
can be deployed via securityfs. The boot policy can be specified via the
Kconfig, `SECURITY_IPE_BOOT_POLICY`, which accepts a path to a plain-text
version of the IPE policy to apply. This policy will be compiled into the
kernel. If not specified, IPE will be disabled until a policy is deployed
through securityfs, and activated through sysfs.

## Modes

IPE, similar to SELinux, supports two modes of operation: permissive
and enforce. Permissive mode performs the same checks as enforce mode,
and logs policy violations, but will not enforce the policy. This allows
users to test policies before enforcing them.

The default mode is enforce, and can be changed via the kernel command line
parameter `ipe.enforce=(0|1)`, or the securityfs node,
`/sys/kernel/security/ipe/enforce`. The ability to switch modes can be compiled
out of the LSM via setting the Kconfig `CONFIG_SECURITY_IPE_PERMISSIVE_SWITCH` to N.
