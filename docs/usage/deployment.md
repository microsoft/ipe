# Deploying Policies

Policies can be deployed from userspace through securityfs. These policies are signed through the PKCS#7 message format to enforce some level of authorization of the policies (prohibiting an attacker from gaining unconstrained root, and deploying an "allow all" policy). These policies must be signed by a certificate that chains to the `SYSTEM_TRUSTED_KEYRING`. With openssl, the policy can be signed by:

```
openssl smime -sign \
   -in "$MY_POLICY" \
   -signer "$MY_CERTIFICATE" \
   -inkey "$MY_PRIVATE_KEY" \
   -noattr \
   -nodetach \
   -nosmimecap \
   -outform der \
   -out "$MY_POLICY.p7b"
```

Deploying the policies is done through securityfs, through the `new_policy` node. To deploy a policy, simply cat the file into the securityfs node:

```
cat "$MY_POLICY.p7b" > /sys/kernel/security/ipe/new_policy
```

Upon success, this will create one subdirectory under `/sys/kernel/security/ipe/policies/`. The subdirectory will be the `policy_name` field of the policy deployed, so for the example above, the directory will be `/sys/kernel/security/ipe/policies/Ex_Policy`. Within this directory, there will be seven files: `pkcs7`, `policy`, `name`, `version`, `active`, `update`, and `delete`.

The `pkcs7` file is read-only. Reading it returns the raw PKCS#7 data that was provided to the kernel, representing the policy. If the policy being read is the boot policy, this will return `ENOENT`, as it is not signed.

The `policy` file is read only. Reading it returns the PKCS#7 inner content of the policy, which will be the plain text policy.

The `active` file is used to set a policy as the currently active policy. This file is rw, and accepts a value of `"1"` to set the policy as active. Since only a single policy can be active at one time, all other policies will be marked inactive. The policy being marked active must have a policy version greater or equal to the currently-running version.

The `update` file is used to update a policy that is already present in the kernel. This file is write-only and accepts a PKCS#7 signed policy. Two checks will always be performed on this policy: First, the `policy_names` must match with the updated version and the existing version. Second the updated policy must have a policy version greater than or equal to the currently-running version. This is to prevent rollback attacks.

The `delete` file is used to remove a policy that is no longer needed. This file is write-only and accepts a value of `"1"` to delete the policy. On deletion, the securityfs node representing the policy will be removed. However, delete the current active policy is not allowed and will return an operation not permitted error.

Similarly, writing to both `update` and `new_policy` could result in bad message(policy syntax error) or file exists error. The latter error happens when trying to deploy a policy with a `policy_name` while the kernel already has a deployed policy with the same `policy_name`.

Deploying a policy will *not* cause IPE to start enforcing the policy. IPE will only enforce the policy marked active. Note that only one policy can be active at a time.

Once deployment is successful, the policy can be activated, by writing file `/sys/kernel/security/ipe/policies/$policy_name/active`. For example, the `Ex_Policy` can be activated by:

```
echo 1 > "/sys/kernel/security/ipe/policies/Ex_Policy/active"
```

From above point on, `Ex_Policy` is now the enforced policy on the system.

IPE also provides a way to delete policies. This can be done via the `delete` securityfs node, `/sys/kernel/security/ipe/policies/$policy_name/delete`. Writing `1` to that file deletes the policy:

```
echo 1 > "/sys/kernel/security/ipe/policies/$policy_name/delete"
```

There is only one requirement to delete a policy: the policy being deleted must be inactive.

**NOTE:**

If a traditional MAC system is enabled (SELinux, apparmor, smack), all writes to ipe's securityfs nodes require `CAP_MAC_ADMIN`.
