/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

/**
 * curl CLI Fuzzer
 *
 * This fuzzer targets the curl command-line tool (src/tool_operate.c) rather
 * than the libcurl library. It fuzzes the operate(), run_all_transfers(),
 * serial_transfers(), and parallel_transfers() functions.
 *
 * SAFETY CONSTRAINTS:
 * - No network I/O: Only file: and data: protocols allowed
 * - Bounded runtime: Max 1 second per iteration with timeouts
 * - Deterministic: No config files, no environment dependencies
 * - No persistent side effects: All I/O in temp directory, cleaned up
 * - Valid URLs: Always provide at least one valid URL
 * - Option allowlist: Safe CLI flags only
 */

/* Uncomment to enable argv debug output */
/* #define FUZZER_DEBUG_ARGV */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <dirent.h>
#include <assert.h>
#include <stdbool.h>

/* Curl CLI headers */
#include "tool_setup.h"
#include "tool_cfgable.h"
#include "tool_operate.h"
#include "tool_cb_dbg.h"  /* For trace enum */
#include "tool_stderr.h"  /* For tool_init_stderr */

/* libcurl for global init/cleanup */
#include <curl/curl.h>

/* Forward declarations (already in tool_cfgable.h but repeated for clarity) */
extern struct GlobalConfig *global;

/* One-time initialization for the fuzzer */
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;

    /* Initialize tool stderr (required for operate()) */
    tool_init_stderr();

    return 0;
}

/* Fuzz input format:
 * Byte 0:     Flags byte
 *             Bit 0: Enable --parallel
 *             Bit 1: Add --next (multiple URLs)
 *             Bits 2-7: Reserved
 * Byte 1-2:   Number of args to generate (N) - big endian
 * Byte 3+:    Arg TLVs [type:1][len:1][value:len] (N times)
 * Remaining:  File content data
 */

#define FLAG_PARALLEL  0x01
#define FLAG_NEXT      0x02

#define MAX_ARGS       128
#define MAX_ARG_LEN    256
#define MAX_TEMP_PATH  512
#define SAFETY_ARGS_COUNT 14  /* Must match add_safety_args() count */

/* Argument types that can be parsed from fuzz input */
enum arg_type {
    ARG_OUTPUT = 1,
    ARG_VERBOSE = 2,
    ARG_SHOW_ERROR = 3,
    ARG_REQUEST = 4,
    ARG_DATA = 5,
    ARG_DATA_RAW = 6,
    ARG_DATA_BINARY = 7,
    ARG_HEADER = 8,
    ARG_USER_AGENT = 9,
    ARG_REFERER = 10,
    ARG_LOCATION = 11,
    ARG_MAX_REDIRS = 12,
    ARG_COMPRESSED = 13,
    ARG_RANGE = 14,
    ARG_WRITE_OUT = 15
};

/* Helper function to create a unique temporary directory */
static int create_temp_directory(char *buf, size_t size) {
    snprintf(buf, size, "/tmp/curl_fuzz_%d_%ld", getpid(), (long)time(NULL));

    if(mkdir(buf, 0700) != 0) {
        if(errno != EEXIST) {
            return -1;
        }
    }
    return 0;
}

/* Helper function to write fuzz data to a file */
static int write_fuzz_data_to_file(const char *path, const uint8_t *data,
                                     size_t size) {
    FILE *fp = fopen(path, "wb");
    if(!fp) {
        return -1;
    }

    size_t written = fwrite(data, 1, size, fp);
    fclose(fp);

    return (written == size) ? 0 : -1;
}

/* Helper function to recursively remove directory contents */
static void remove_directory_contents(const char *path) {
    DIR *dir = opendir(path);
    if(!dir) {
        return;
    }

    struct dirent *entry;
    while((entry = readdir(dir)) != NULL) {
        if(strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char filepath[MAX_TEMP_PATH];
        snprintf(filepath, sizeof(filepath), "%s/%s", path, entry->d_name);
        unlink(filepath);
    }

    closedir(dir);
}

/* Helper function to cleanup temp directory */
static void cleanup_temp_directory(const char *temp_dir) {
    remove_directory_contents(temp_dir);
    rmdir(temp_dir);
}

/* Helper function to add safety arguments that are always injected */
static int add_safety_args(char **argv, int *argc) {
    int start_argc = *argc;

    /* Configuration isolation - skip config file parsing (MUST BE FIRST)
     * -q is checked as first_arg in operate.c:2256 to skip .curlrc */
    argv[(*argc)++] = "-q";        /* Must be argv[1] */
    argv[(*argc)++] = "--disable";

    /* CRITICAL: Protocol restriction - prevent all network I/O
     * Note: Only 'file' protocol is used. 'data' URLs are not supported by curl. */
    argv[(*argc)++] = "--proto";
    argv[(*argc)++] = "file";
    argv[(*argc)++] = "--proto-redir";
    argv[(*argc)++] = "file";

    /* Time bounds - max 1 second timeout */
    argv[(*argc)++] = "--max-time";
    argv[(*argc)++] = "1";
    argv[(*argc)++] = "--connect-timeout";
    argv[(*argc)++] = "1";
    argv[(*argc)++] = "--retry";
    argv[(*argc)++] = "0";

    /* Output control - reduce noise */
    argv[(*argc)++] = "--no-progress-meter";
    argv[(*argc)++] = "--silent";

    int added_count = *argc - start_argc;
    /* If this assertion fails, update SAFETY_ARGS_COUNT in cleanup_argv */
    assert(added_count == SAFETY_ARGS_COUNT &&
           "Safety args count mismatch - update SAFETY_ARGS_COUNT!");

    return 0;
}

/* Track allocated strings for cleanup */
static char *allocated_strings[MAX_ARGS];
static int allocated_count = 0;

/* Helper to track and allocate a string */
static char *tracked_malloc(size_t size) {
    char *ptr = malloc(size);
    if(ptr && allocated_count < MAX_ARGS) {
        allocated_strings[allocated_count++] = ptr;
    }
    return ptr;
}

/* Helper to untrack a string (when we free it early) */
static void untrack_string(char *ptr) {
    for(int i = 0; i < allocated_count; i++) {
        if(allocated_strings[i] == ptr) {
            allocated_strings[i] = NULL;
            return;
        }
    }
}

/* Helper function to sanitize string for use in arguments */
static void sanitize_string(char *str, size_t len) {
    for(size_t i = 0; i < len && str[i]; i++) {
        /* Replace null bytes and control characters with spaces */
        if(str[i] < 32 || str[i] == 127) {
            str[i] = ' ';
        }
    }
}

/* Check if argument value starts with @ (curl's @file syntax)
 * If so, DROP the entire option/value to prevent file reads */
static bool is_atfile_value(const char *str) {
    return (str && str[0] == '@');
}

/* Helper function to parse fuzz input into arguments (allowlist only) */
static int parse_fuzz_args(const uint8_t *data, size_t size, char **argv,
                            int *argc, const char *temp_dir, size_t *offset) {
    if(size < 3) {
        *offset = size;
        return 0;
    }

    /* Parse number of arguments (bytes 1-2, big endian) */
    uint16_t num_args = ((uint16_t)data[1] << 8) | data[2];

    /* SECURITY: Reject obviously malformed input early to prevent
     * processing garbage data that could trigger crashes.
     * If num_args is unreasonably large, this is likely not a valid
     * fuzzer input (e.g., HTTP response being interpreted as TLV). */
    if(num_args > 256) {
        /* Invalid input format - reject */
        *offset = size;
        return 0;
    }

    /* Cap to reasonable number for actual processing */
    if(num_args > 20) {
        num_args = 20;
    }

    size_t pos = 3;

    for(uint16_t i = 0; i < num_args && pos + 2 <= size && *argc < MAX_ARGS - 10; i++) {
        if(pos + 2 > size) break;

        uint8_t type = data[pos++];
        uint8_t len = data[pos++];

        if(pos + len > size) break;

        char *arg_value = NULL;

        /* Cap argument length */
        if(len > MAX_ARG_LEN - 1) {
            len = MAX_ARG_LEN - 1;
        }

        switch(type) {
            case ARG_OUTPUT: {
                /* Output to temp directory */
                char *output_path = tracked_malloc(MAX_TEMP_PATH);
                if(output_path) {
                    snprintf(output_path, MAX_TEMP_PATH, "%s/output.txt", temp_dir);
                    argv[(*argc)++] = "--output";
                    argv[(*argc)++] = output_path;
                }
                break;
            }

            case ARG_VERBOSE:
                argv[(*argc)++] = "--verbose";
                break;

            case ARG_SHOW_ERROR:
                argv[(*argc)++] = "--show-error";
                break;

            case ARG_REQUEST:
                if(len > 0) {
                    arg_value = tracked_malloc(len + 1);
                    if(arg_value) {
                        memcpy(arg_value, data + pos, len);
                        arg_value[len] = '\0';
                        sanitize_string(arg_value, len);

                        /* Only allow safe HTTP methods */
                        if(strncmp(arg_value, "GET", 3) == 0 ||
                           strncmp(arg_value, "POST", 4) == 0 ||
                           strncmp(arg_value, "PUT", 3) == 0 ||
                           strncmp(arg_value, "DELETE", 6) == 0 ||
                           strncmp(arg_value, "HEAD", 4) == 0 ||
                           strncmp(arg_value, "OPTIONS", 7) == 0) {
                            argv[(*argc)++] = "--request";
                            argv[(*argc)++] = arg_value;
                        } else {
                            /* Invalid HTTP method - untrack and free */
                            untrack_string(arg_value);
                            free(arg_value);
                        }
                    }
                }
                break;

            case ARG_DATA:
            case ARG_DATA_RAW:
            case ARG_DATA_BINARY:
                if(len > 0) {
                    arg_value = tracked_malloc(len + 1);
                    if(arg_value) {
                        memcpy(arg_value, data + pos, len);
                        arg_value[len] = '\0';

                        /* DROP this argument if it starts with @ */
                        if(is_atfile_value(arg_value)) {
                            untrack_string(arg_value);
                            free(arg_value);
                            /* Don't add to argv - just skip this TLV */
                        } else {
                            if(type == ARG_DATA) {
                                argv[(*argc)++] = "--data";
                            } else if(type == ARG_DATA_RAW) {
                                argv[(*argc)++] = "--data-raw";
                            } else {
                                argv[(*argc)++] = "--data-binary";
                            }
                            argv[(*argc)++] = arg_value;
                        }
                    }
                }
                break;

            case ARG_HEADER:
                if(len > 0) {
                    arg_value = tracked_malloc(len + 1);
                    if(arg_value) {
                        memcpy(arg_value, data + pos, len);
                        arg_value[len] = '\0';
                        sanitize_string(arg_value, len);

                        /* DROP this argument if it starts with @ */
                        if(is_atfile_value(arg_value)) {
                            untrack_string(arg_value);
                            free(arg_value);
                            /* Don't add to argv - just skip this TLV */
                        } else {
                            argv[(*argc)++] = "--header";
                            argv[(*argc)++] = arg_value;
                        }
                    }
                }
                break;

            case ARG_USER_AGENT:
                if(len > 0) {
                    arg_value = tracked_malloc(len + 1);
                    if(arg_value) {
                        memcpy(arg_value, data + pos, len);
                        arg_value[len] = '\0';
                        sanitize_string(arg_value, len);

                        /* DROP this argument if it starts with @ */
                        if(is_atfile_value(arg_value)) {
                            untrack_string(arg_value);
                            free(arg_value);
                            /* Don't add to argv - just skip this TLV */
                        } else {
                            argv[(*argc)++] = "--user-agent";
                            argv[(*argc)++] = arg_value;
                        }
                    }
                }
                break;

            case ARG_REFERER:
                if(len > 0) {
                    arg_value = tracked_malloc(len + 1);
                    if(arg_value) {
                        memcpy(arg_value, data + pos, len);
                        arg_value[len] = '\0';
                        sanitize_string(arg_value, len);

                        /* DROP this argument if it starts with @ */
                        if(is_atfile_value(arg_value)) {
                            untrack_string(arg_value);
                            free(arg_value);
                            /* Don't add to argv - just skip this TLV */
                        } else {
                            argv[(*argc)++] = "--referer";
                            argv[(*argc)++] = arg_value;
                        }
                    }
                }
                break;

            case ARG_LOCATION:
                argv[(*argc)++] = "--location";
                break;

            case ARG_MAX_REDIRS:
                if(len > 0) {
                    arg_value = tracked_malloc(16);
                    if(arg_value) {
                        /* Use first byte as redirect count, cap at 5 */
                        uint8_t count = data[pos] % 6;
                        snprintf(arg_value, 16, "%u", count);
                        argv[(*argc)++] = "--max-redirs";
                        argv[(*argc)++] = arg_value;
                    }
                }
                break;

            case ARG_COMPRESSED:
                argv[(*argc)++] = "--compressed";
                break;

            case ARG_RANGE:
                if(len > 0) {
                    arg_value = tracked_malloc(len + 1);
                    if(arg_value) {
                        memcpy(arg_value, data + pos, len);
                        arg_value[len] = '\0';
                        sanitize_string(arg_value, len);

                        /* DROP this argument if it starts with @ */
                        if(is_atfile_value(arg_value)) {
                            untrack_string(arg_value);
                            free(arg_value);
                            /* Don't add to argv - just skip this TLV */
                        } else {
                            argv[(*argc)++] = "--range";
                            argv[(*argc)++] = arg_value;
                        }
                    }
                }
                break;

            case ARG_WRITE_OUT:
                if(len > 0) {
                    arg_value = tracked_malloc(len + 1);
                    if(arg_value) {
                        memcpy(arg_value, data + pos, len);
                        arg_value[len] = '\0';
                        sanitize_string(arg_value, len);

                        /* DROP this argument if it starts with @ */
                        if(is_atfile_value(arg_value)) {
                            untrack_string(arg_value);
                            free(arg_value);
                            /* Don't add to argv - just skip this TLV */
                        } else {
                            argv[(*argc)++] = "--write-out";
                            argv[(*argc)++] = arg_value;
                        }
                    }
                }
                break;

            default:
                /* Unknown type, skip */
                break;
        }

        pos += len;
    }

    *offset = pos;
    return 0;
}

/* Helper function to cleanup allocated argv strings
 *
 * IMPORTANT: We MUST free all allocated strings after operate() returns because
 * curl makes copies of argv strings rather than taking ownership. The strings we
 * allocate are only used during argument parsing, then curl stores copies in its
 * internal config structures.
 *
 * Freeing them here prevents memory leaks and is safe because:
 * 1. operate() has already returned, so it's done reading from argv
 * 2. curl has made copies of any strings it needs
 * 3. globalconf_free() will free curl's internal copies later */
static void cleanup_argv(void) {
    for(int i = 0; i < allocated_count; i++) {
        if(allocated_strings[i]) {
            free(allocated_strings[i]);
            allocated_strings[i] = NULL;
        }
    }
    allocated_count = 0;
}

/* Main fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Minimum size check */
    if(size < 4) {
        return 0;
    }

    /* Ignore SIGPIPE to prevent crashes from broken pipes */
    signal(SIGPIPE, SIG_IGN);

    /* Initialize global config (required for operate())
     * NOTE: This must be called each iteration because operate() modifies global state.
     * However, globalconf_init() doesn't fully reset the static globalconf struct,
     * which can cause state leakage between iterations. */
    if(globalconf_init() != CURLE_OK) {
        return 0;
    }

    /* Parse control flags */
    uint8_t flags = data[0];

    /* Create temporary directory */
    char temp_dir[MAX_TEMP_PATH];
    if(create_temp_directory(temp_dir, sizeof(temp_dir)) != 0) {
        return 0;
    }

    /* Set environment isolation */
    setenv("HOME", temp_dir, 1);
    setenv("CURL_HOME", temp_dir, 1);

    /* Clear potentially harmful environment variables */
    unsetenv("http_proxy");
    unsetenv("https_proxy");
    unsetenv("ftp_proxy");
    unsetenv("all_proxy");
    unsetenv("HTTP_PROXY");
    unsetenv("HTTPS_PROXY");
    unsetenv("FTP_PROXY");
    unsetenv("ALL_PROXY");

    /* Parse arguments from fuzz input */
    size_t file_data_offset = 0;
    char *argv[MAX_ARGS];
    int argc = 0;

    argv[argc++] = "curl";

    /* Add safety arguments */
    add_safety_args(argv, &argc);

    /* Parse fuzz input into arguments */
    parse_fuzz_args(data, size, argv, &argc, temp_dir, &file_data_offset);

    /* Add parallel flag if requested */
    if(flags & FLAG_PARALLEL) {
        argv[argc++] = "--parallel";
    }

    /* Write fuzz data to input file */
    char input_file[MAX_TEMP_PATH];
    snprintf(input_file, sizeof(input_file), "%s/input.dat", temp_dir);

    size_t file_data_size = (file_data_offset < size) ? (size - file_data_offset) : 0;
    const uint8_t *file_data = (file_data_offset < size) ? (data + file_data_offset) : data;

    /* Write at least 1 byte to ensure file exists */
    if(file_data_size == 0) {
        file_data = (const uint8_t *)"";
        file_data_size = 0;
    }

    if(write_fuzz_data_to_file(input_file, file_data, file_data_size) != 0) {
        cleanup_temp_directory(temp_dir);
        return 0;
    }

    /* Construct file:// URL */
    char *url = tracked_malloc(MAX_TEMP_PATH + 32);
    if(!url) {
        cleanup_temp_directory(temp_dir);
        return 0;
    }
    snprintf(url, MAX_TEMP_PATH + 32, "file://%s", input_file);
    argv[argc++] = url;

    /* Add second URL with --next if requested */
    char input_file2[MAX_TEMP_PATH];
    char *url2 = NULL;
    if(flags & FLAG_NEXT) {
        argv[argc++] = "--next";

        /* Create second file with different data */
        snprintf(input_file2, sizeof(input_file2), "%s/input2.dat", temp_dir);

        /* Use first part of data for second file */
        size_t second_file_size = (size > 1024) ? 1024 : size;
        if(write_fuzz_data_to_file(input_file2, data, second_file_size) == 0) {
            url2 = tracked_malloc(MAX_TEMP_PATH + 32);
            if(url2) {
                snprintf(url2, MAX_TEMP_PATH + 32, "file://%s", input_file2);
                argv[argc++] = url2;
            }
        }
    }

    /* Null-terminate argv */
    argv[argc] = NULL;

#ifdef FUZZER_DEBUG_ARGV
    /* Debug: Print argv to verify correct construction */
    fprintf(stderr, "=== FUZZER ARGV (argc=%d) ===\n", argc);
    for(int i = 0; i < argc; i++) {
        fprintf(stderr, "argv[%d] = %s\n", i, argv[i] ? argv[i] : "(null)");
    }
    fprintf(stderr, "=== END ARGV ===\n");
#endif

    /* Redirect stdout/stderr to /dev/null to reduce noise */
    /* Note: Disabled for debugging, can be re-enabled later */
    /* int saved_stdout = dup(STDOUT_FILENO);
    int saved_stderr = dup(STDERR_FILENO);
    int devnull = open("/dev/null", O_WRONLY);
    if(devnull >= 0) {
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        close(devnull);
    } */

    /* Call curl CLI operate function - NO CAST! */
    CURLcode result = operate(argc, argv);
    (void)result; /* Ignore result code */

    /* Restore stdout/stderr */
    /* if(saved_stdout >= 0) {
        dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);
    }
    if(saved_stderr >= 0) {
        dup2(saved_stderr, STDERR_FILENO);
        close(saved_stderr);
    } */

    /* Cleanup allocated strings and temp directory */
    cleanup_argv();
    cleanup_temp_directory(temp_dir);

    /* Global cleanup to prevent state leakage between iterations
     * IMPORTANT: globalconf_free() calls curl_global_cleanup() internally.
     * This is expensive but necessary to properly reset libcurl's global state.
     *
     * BUG FIX: globalconf_free() does not reset several fields, which can cause
     * crashes on the next iteration. We must explicitly reset these fields. */
    globalconf_free();

    /* Reset trace-related fields that aren't cleared by globalconf_free() */
    global->tracetype = TRACE_NONE;
    global->traceids = FALSE;
    global->tracetime = FALSE;
    global->trace_set = FALSE;

    /* Reset state structure to prevent use-after-free
     * BUG FIX: global->state.urlnode can point to freed memory after config_free()
     * This causes heap-use-after-free in create_single() on next iteration */
    memset(&global->state, 0, sizeof(global->state));

    return 0;
}
