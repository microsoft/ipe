## Deploying Policies

User policies are policies that are deployed from userland, through securityfs. 
These policies are signed to enforce some level of authorization of the policies 
(prohibiting an attacker from gaining root, and deploying an "allow all" policy), 
through the PKCS#7 enveloped data format. These policies must be signed by a certificate
that chains to the `SYSTEM_TRUSTED_KEYRING`. Through openssl, the signing
can be done via:

```
openssl smime -sign -in "$MY_POLICY" -signer "$MY_CERTIFICATE" \
  -inkey "$MY_PRIVATE_KEY" -binary -outform der -noattr -nodetach \
  -out "$MY_POLICY.p7s"
```

Deploying the policies is done through securityfs, through the
`new_policy` node. To deploy a policy, simply cat the file into the
securityfs node:

```
cat "$MY_POLICY.p7s" > /sys/kernel/security/ipe/new_policy
```

Upon success, this will create one subdirectory under
`/sys/kernel/security/ipe/policies/`. The subdirectory will be the
`policy_name` field of the policy deployed, so for the example above, the
directory will be `/sys/kernel/security/ipe/policies/Ex\ Policy`. Within
this directory, there will be two files: `raw` and `content`. 

The `raw` file is rw, reading will provide the raw PKCS#7 data that
was provided to the kernel, representing the policy. Writing, will deploy
an in-place policy update - if this policy is the currently running policy,
the new updated policy will replace it immediately upon success.

The `content` file is read only. Reading will provide the PKCS#7 inner
content of the policy, which will be the plain text policy.

Similarly, the `cat` command above will result in an error upon
syntactically invalid or untrusted policies. It will also error if a
policy already exists with the same `policy_name`. The write to the `raw`
node will error upon syntactically invalid, untrusted policies, or if the
payload fails the version check. The write will also fail if the
`policy_name` in the payload does not match the existing policy.

## Activating Policies

Deploying these policies will _not_ cause IPE to start enforcing this
policy. Once deployment is successful, a policy can be marked as active,
via the sysctl, `ipe.active_policy`. IPE will enforce whatever policy is
marked as active. For our example, we can activate the `Ex Policy` via:

```
sysctl ipe.active_policy="Ex Policy"
```

At which point, `Ex Policy` will now be the enforced policy on the system.

## Deleting Policies

IPE also provides a way to delete policies. This can be done via the
`del_policy` securityfs node, `/sys/kernel/security/ipe/del_policy`.
Writing the `policy_name` of the policy to be deleted will delete that
node: 

```
echo -n "$MY_POLICY_NAME" > /sys/kernel/security/ipe/del_policy
```

There are two requirements to delete policies:

1. The policy being deleted must not be the active policy.
2. The policy being deleted must not be the boot policy.

NOTE: It's important to know above that the "echo" command will add a
newline to the end of the input, and this will be considered as part of the
filename. You can remove the newline via the -n parameter.
