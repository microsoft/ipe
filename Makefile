CC=gcc
WFLAGS=-Werror -Wextra -Wpedantic
SRC=src
VOL=vol
VOL_FSVERITY=vol_fsverity
OUTPUT=output
PYTHON=python3
POLICY=policies

all: hello hellosh hellolib memfd_test mmap_test mprotect_test copy_lib copy_bin $(VOL) $(VOL_FSVERITY)

$(VOL):
	mkdir -p $(VOL)
	mkdir -p $(VOL)/bin
	mkdir -p $(VOL)/lib
	mkdir -p $(VOL)/script

$(VOL_FSVERITY): $(VOL)
	rm -rf $(VOL_FSVERITY)
	cp -r $(VOL) $(VOL_FSVERITY)
	python3 tools/format_verified_directory.py -d $(VOL_FSVERITY) -v $(VOL_FSVERITY)
	find $(VOL_FSVERITY) -type f -exec sh -c "fsverity sign {} {}.sig --key=$(KEY)  --cert=$(CERT)" \;
	find $(VOL_FSVERITY) -type f -not -name "*.sig" -exec sh -c "fsverity enable {} --signature={}.sig" \;
	python3 tools/gen_fsverity_hash_policy.py -p $(POLICY) -v $(VOL_FSVERITY)

copy_lib: $(VOL)/lib/libc.so.6 $(VOL)/lib/ld-linux.so
$(VOL)/lib/libc.so.6:
	cp /lib/x86_64-linux-gnu/libc.so.6 $(VOL)/lib/libc.so.6
$(VOL)/lib/ld-linux.so:
	cp /lib64/ld-linux-x86-64.so.2 $(VOL)/lib/ld-linux.so

copy_bin: $(VOL)/bin/sh
$(VOL)/bin/sh: $(VOL)
	cp /bin/sh $(VOL)/bin

hello: $(VOL)/bin/hello
$(VOL)/bin/hello: $(VOL)
	$(CC) $(WFLAGS) -o $(VOL)/bin/hello $(SRC)/hello.c

hellosh: $(VOL)/script/hello.sh
$(VOL)/script/hello.sh: $(VOL)
	cp $(SRC)/hello.sh $(VOL)/script/hello.sh

hellolib: $(VOL)/lib/libhello.so
$(VOL)/lib/libhello.so: $(VOL)
	$(CC) $(WFLAGS) -o $(VOL)/lib/libhello.so --shared -fPIC $(SRC)/libhello.c

memfd_test: $(VOL)/bin/memfd_test
$(VOL)/bin/memfd_test: $(VOL)
	$(CC) $(WFLAGS) -o $(VOL)/bin/memfd_test $(SRC)/memfd_test.c

mmap_test: $(VOL)/bin/mmap_test
$(VOL)/bin/mmap_test: $(VOL)
	$(CC) $(WFLAGS) -o $(VOL)/bin/mmap_test $(SRC)/mmap_test.c

mprotect_test: $(VOL)/bin/mprotect_test
$(VOL)/bin/mprotect_test: $(VOL)
	$(CC) $(WFLAGS) -o $(VOL)/bin/mprotect_test $(SRC)/mprotect_test.c

prepare_test:
	mkdir -p $(OUTPUT)
	$(PYTHON) tools/format_volume.py -o $(OUTPUT) -d $(VOL) -k $(KEY) -c $(CERT)
	$(PYTHON) tools/update_dmv_policy_roothash.py -p $(POLICY) -r $(OUTPUT)/$(shell basename $(VOL)).roothash
	$(PYTHON) tools/sign_policy.py -k $(KEY) -c $(CERT) -p $(POLICY)

allow_all:
	@if [ ! -d /sys/kernel/security/ipe/policies/allow_all ]; then \
                cat $(POLICY)/test_func/p7s/allow_all.p7s > /sys/kernel/security/ipe/new_policy; \
        fi

test: prepare_test allow_all
	$(PYTHON) test/main.py -n $(OUTPUT)/$(shell basename $(VOL)) -f $(VOL_FSVERITY) -p $(POLICY) --simple --mem --linker --load-policy

clean: clean_vol clean_output clean_vol_fsverity

clean_vol:
	rm -rf $(VOL)

clean_vol_fsverity:
	rm -rf $(VOL_FSVERITY)

clean_output:
	rm -rf $(OUTPUT)
