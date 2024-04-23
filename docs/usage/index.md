# Policy

IPE policy is a plain-text policy composed of multiple statements over several lines. There is one required line, at the top of the policy, indicating the policy name, and the policy version, for instance:

`policy_name=Ex_Policy policy_version=0.0.0`

The policy name is a unique key identifying this policy in a human readable name. This is used to create nodes under securityfs as well as uniquely identify policies to deploy new policies vs update existing policies.

The policy version indicates the current version of the policy (NOT the policy syntax version). This is used to prevent rollback of policy to potentially insecure previous versions of the policy.

The next portion of IPE policy are rules. Rules are formed by key=value pairs, known as properties. IPE rules require two properties: `action`, which determines what IPE does when it encounters a match against the rule, and `op`, which determines when the rule should be evaluated. The ordering is significant, a rule must start with `op`, and end with `action`. Thus, a minimal rule is:

`op=EXECUTE action=ALLOW`

This example will allow any execution. Additional properties are used to assess immutable security properties about the files being evaluated. These properties are intended to be descriptions of systems within the kernel that can provide a measure of integrity verification, such that IPE can determine the trust of the resource based on the value of the property.

Rules are evaluated top-to-bottom. As a result, any revocation rules, or denies should be placed early in the file to ensure that these rules are evaluated before a rule with `action=ALLOW`.

IPE policy supports comments. The character '#' will function as a comment, ignoring all characters to the right of '#' until the newline.

The default behavior of IPE evaluations can also be expressed in policy, through the `DEFAULT` statement. This can be done at a global level, or a per-operation level:
```
#Global
DEFAULT action=ALLOW

#Operation Specific
DEFAULT op=EXECUTE action=ALLOW
```

A default must be set for all known operations in IPE. If you want to preserve older policies being compatible with newer kernels that can introduce new operations, set a global default of `ALLOW`, then override the defaults on a per-operation basis (as above).

With configurable policy-based LSMs, there's several issues with enforcing the configurable policies at startup, around reading and parsing the policy:

1. The kernel *should* not read files from userspace, so directly reading the policy file is prohibited.
2. The kernel command line has a character limit, and one kernel module should not reserve the entire character limit for its own configuration.
3. There are various boot loaders in the kernel ecosystem, so handing off a memory block would be costly to maintain.

As a result, IPE has addressed this problem through a concept of a "boot policy". A boot policy is a minimal policy which is compiled into the kernel. This policy is intended to get the system to a state where userspace is set up and ready to receive commands, at which point a more complex policy can be deployed via securityfs. The boot policy can be specified via `SECURITY_IPE_BOOT_POLICY` config option, which accepts a path to a plain-text version of the IPE policy to apply. This policy will be compiled into the kernel. If not specified, IPE will be disabled until a policy is deployed and activated through securityfs.

# Modes

IPE supports two modes of operation: permissive (similar to SELinux's permissive mode) and enforced. In permissive mode, all events are checked and policy violations are logged, but the policy is not really enforced. This allows users to test policies before enforcing them.

The default mode is enforce, and can be changed via the kernel command line parameter `ipe.enforce=(0|1)`, or the securityfs node `/sys/kernel/security/ipe/enforce`.

**NOTE:**

If a traditional MAC system is enabled (SELinux, apparmor, smack, etcetera), all writes to ipe's securityfs nodes require `CAP_MAC_ADMIN`.
