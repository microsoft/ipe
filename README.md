# IPE Test Suite

The IPE test suite contains various test cases designed to test policy loading and policy functionality. All test cases have been verified on Ubuntu 22.04 LTS x86_64.

## Quick Start

```bash
make KEY=PATH/TO/KERNEL/TRUSTED/KEY.pem CERT=PATH/TO/THE/CERT.pem
make test KEY=PATH/TO/KERNEL/TRUSTED/KEY.pem CERT=PATH/TO/THE/CERT.pem
```
Running the above commands will execute the policy loading tests and functionality tests.

## Dependencies

The following dependencies are required:

- Python 3
- patchelf
- veritysetup 2.3.0+ (To use the --root-hash-signature option)
- fsverity
- gcc
- keyutils

You can install all dependencies using the following command:

```bash
apt install build-essential patchelf fsverity keyutils
```

## Preparing for Testing

The test suite provides a straightforward way to build the binary resources needed for testing. Run the following command:

```bash
make
```
The `vol` directory will contain all the required resources.

To format `vol` into a volume, run:

```bash
make prepare_test KEY=PATH/TO/KERNEL/TRUSTED/KEY.pem CERT=PATH/TO/THE/CERT.pem
```
The formatted volume will be located inside the `output` directory. This command will also update the roothash value inside the test policy to match the roothash of the formatted volume.

## Policy Loading Tests

To run the policy loading tests, execute:

```bash
python test/main.py -p ./policies --load-policy
```

## DMVerity Related Tests

To test the DMVerity related policies, execute:

```bash
python test/main.py -p ./policies (test options e.g. --simple) -n ./output/vol
```

## FSVerity Related Tests

Before running FSVerity related tests, FSVerity needs to be enabled on the file system. Use the following command to enable FSVerity:

```bash
tune2fs -O verity /dev/(target_device)
```
Additionally, the `.fs-verity` keyring needs to be configured. Use the following command to load the trusted certificate in DER format:

```bash
keyctl padd asymmetric '' %keyring:.fs-verity < cert.der
```

To test the FSVerity related policies, execute:

```bash
python test/main.py -p ./policies (test options e.g. --simple) -f ./vol_fsverity
```
