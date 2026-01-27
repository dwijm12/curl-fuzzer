/*
 * Simple test program for curl CLI fuzzer to debug issues
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* Declare the fuzzer entry point */
extern int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size);

int main(int argc, char **argv) {
    if(argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if(!fp) {
        perror("fopen");
        return 1;
    }

    /* Get file size */
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if(size <= 0 || size > 1024 * 1024) {
        fprintf(stderr, "Invalid file size: %ld\n", size);
        fclose(fp);
        return 1;
    }

    /* Read file */
    unsigned char *data = malloc(size);
    if(!data) {
        perror("malloc");
        fclose(fp);
        return 1;
    }

    size_t read_size = fread(data, 1, size, fp);
    fclose(fp);

    if(read_size != (size_t)size) {
        fprintf(stderr, "Read error: got %zu, expected %ld\n", read_size, size);
        free(data);
        return 1;
    }

    printf("Testing with %ld bytes of input...\n", size);

    /* Call the fuzzer */
    int result = LLVMFuzzerTestOneInput(data, size);

    printf("Fuzzer returned: %d\n", result);

    free(data);
    return 0;
}
