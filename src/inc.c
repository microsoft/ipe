/*
 * Integrity Policy Enforcement Test Suite
 * Copyright (C) Microsoft Corporation. All rights reserved.
 *
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
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
	const char *prefix = "echo \"";
	size_t prefix_len = strlen(prefix);

	saveptr = NULL;
	line = strtok_r(buffer, "\n", &saveptr);
	while (line) {
		// First, skip comment lines and empty lines
		if (*line == '#' || *line == '\0') {
			line = strtok_r(NULL, "\n", &saveptr);
			continue;
		}

		// Check if the line starts with 'echo "'
		if (strncmp(line, prefix, prefix_len) == 0) {
			char *start_quote = line + prefix_len;
			char *end_quote = strchr(start_quote, '"');

			if (end_quote) {
				*end_quote = '\0';
				printf("%s\n", start_quote);
				*end_quote = '"';
			} else {
				fprintf(stderr,
					"# ERROR: Malformed echo command, missing closing quote: %s\n",
					line);
				return 1;
			}
		} else {
			fprintf(stderr, "# ERROR: Unknown command format: %s\n",
				line);
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
	char buf[128] = {0};
	size_t buf_size = sizeof(buf);

	/*
	 * We pass a valid argv and envp to the kernel to emulate a native
	 * script execution.  We must use the script file descriptor instead of
	 * the script path name to avoid race conditions.
	 */
	err = sys_execveat(fileno(script), "", script_argv, envp,
			   AT_EMPTY_PATH | AT_EXECVE_CHECK);
	if (err) {
		int saved_errno = errno;
		perror("ERROR: Script execution check");
		return saved_errno;
	}

	/* Reads script. */
	buf_size = fread(buf, 1, buf_size - 1, script);
	buf[buf_size] = '\0';
	return interpret_buffer(buf, buf_size);
}

int main(const int argc, char *const argv[], char *const *const envp)
{
    char *script_name = NULL;
    FILE *script_file = NULL;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <script.inc>\n", argv[0]);
        return 1;
    }
    script_name = argv[1];

    script_file = fopen(script_name, "r");
    if (!script_file) {
        perror("ERROR: Failed to open script");
        return 1;
    }

    // Call interpret_stream directly
    int ret = interpret_stream(script_file, script_name, envp);
    fclose(script_file);
    return ret;
}
