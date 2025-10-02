// SPDX-License-Identifier: BSD-3-Clause
/*
 * Very simple script interpreter that can evaluate two different commands (one
 * per line):
 * - "?" to initialize a counter from user's input;
 * - "+" to increment the counter (which is set to 0 by default).
 *
 * This file is adapted from:
 * samples/check-exec/inc.c from the Linux kernel source tree
 *
 * See tools/testing/selftests/exec/check-exec-tests.sh and
 * Documentation/userspace-api/check_exec.rst
 *
 * Copyright © 2024 Microsoft Corporation
 */

#define _GNU_SOURCE
#include <errno.h>
#include <linux/fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>


static int sys_execveat(int dirfd, const char *pathname, char *const argv[],
			char *const envp[], int flags)
{
	return syscall(__NR_execveat, dirfd, pathname, argv, envp, flags);
}

/* Returns 1 on error, 0 otherwise. */
static int interpret_buffer(char *buffer, size_t buffer_size)
{
	char *line, *saveptr = NULL;
	long long number = 0;

	/* Each command is the first character of a line. */
	saveptr = NULL;
	line = strtok_r(buffer, "\n", &saveptr);
	while (line) {
		if (*line != '#' && strlen(line) != 1) {
			fprintf(stderr, "# ERROR: Unknown string\n");
			return 1;
		}
		switch (*line) {
		case '#':
			/* Skips shebang and comments. */
			break;
		case '+':
			/* Increments and prints the number. */
			number++;
			printf("%lld\n", number);
			break;
		case '?':
			/* Reads integer from stdin. */
			fprintf(stderr, "> Enter new number: \n");
			if (scanf("%lld", &number) != 1) {
				fprintf(stderr,
					"# WARNING: Failed to read number from stdin\n");
			}
			break;
		default:
			fprintf(stderr, "# ERROR: Unknown character '%c'\n",
				*line);
			return 1;
		}
		line = strtok_r(NULL, "\n", &saveptr);
	}
	return 0;
}

/* Returns 1 on error, 0 otherwise. */
static int interpret_stream(FILE *script, char *const script_name,
			    char *const *const envp)
{
	int err;
	char *const script_argv[] = { script_name, NULL };
	char buf[128] = {};
	size_t buf_size = sizeof(buf);

	/*
	 * Consult IPE via AT_EXECVE_CHECK before executing the script.
	 * We use path-based execveat() to allow the kernel to properly
	 * evaluate the script's integrity properties.
	 */
	err = sys_execveat(fileno(script), "", script_argv, envp,
			   AT_EMPTY_PATH | AT_EXECVE_CHECK);
	if (err) {
		fprintf(stderr,
			"Script execution denied by security policy (errno=%d)\n", errno);
		return errno;
	}

	/* Reads script. */
	buf_size = fread(buf, 1, buf_size - 1, script);
	return interpret_buffer(buf, buf_size);
}

static void print_usage(const char *argv0)
{
	fprintf(stderr, "usage: %s <script.inc> | -i | -c <command>\n\n",
		argv0);
	fprintf(stderr, "Examples:\n");
	fprintf(stderr, "  %s script.inc\n", argv0);
	fprintf(stderr, "  %s -i < script.inc\n", argv0);
	fprintf(stderr, "  %s -c '+'\n", argv0);
}

int main(const int argc, char *const argv[], char *const *const envp)
{
	int opt;
	char *cmd = NULL;
	char *script_name = NULL;
	bool interpret_stdin = false;
	FILE *script_file = NULL;
	size_t arg_nb;

	while ((opt = getopt(argc, argv, "c:i")) != -1) {
		switch (opt) {
		case 'c':
			if (cmd) {
				fprintf(stderr, "ERROR: Command already set");
				return 1;
			}
			cmd = optarg;
			break;
		case 'i':
			interpret_stdin = true;
			break;
		default:
			print_usage(argv[0]);
			return 1;
		}
	}

	/* Checks that only one argument is used, or read stdin. */
	arg_nb = !!cmd + !!interpret_stdin;
	if (arg_nb == 0 && argc == 2) {
		script_name = argv[1];
	} else if (arg_nb != 1) {
		print_usage(argv[0]);
		return 1;
	}

	if (cmd) {
		/*
		 * For IPE testing with command-line execution, we also
		 * enforce via AT_EXECVE_CHECK to ensure consistent policy
		 * enforcement across all execution modes.
		 */
		char *const cmd_argv[] = { argv[0], "-c", cmd, NULL };
		int err = sys_execveat(AT_FDCWD, argv[0], cmd_argv, envp, AT_EXECVE_CHECK);
		if (err) {
			fprintf(stderr,
				"Command execution denied by security policy (errno=%d)\n", errno);
			return errno;
		}
		return interpret_buffer(cmd, strlen(cmd));
	}

	if (interpret_stdin && !script_name) {
		script_file = stdin;
		/*
		 * As for any execve(2) call, this path may be logged by the
		 * kernel.
		 */
		script_name = "/proc/self/fd/0";
		/*
		 * For IPE testing with stdin, always enforce via AT_EXECVE_CHECK.
		 */
		return interpret_stream(script_file, script_name, envp);
	} else if (script_name && !interpret_stdin) {
		/*
		 * In this sample, we don't pass any argument to scripts, but
		 * otherwise we would have to forge an argv with such
		 * arguments.
		 */
		script_file = fopen(script_name, "r");
		if (!script_file) {
			perror("ERROR: Failed to open script");
			return 1;
		}
		/*
		 * For IPE testing with script files, always enforce via AT_EXECVE_CHECK.
		 */
		return interpret_stream(script_file, script_name, envp);
	}

	print_usage(argv[0]);
	return 1;
}
