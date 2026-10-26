/*
 * tests/run_tests.c — Combined test runner for pwn4cd unit tests.
 *
 * Compiles and runs all test suites in one binary.
 * Exit code 0 = all pass, 1 = any failure.
 */

#include <stdio.h>
#include <stdlib.h>

/* Declared in each test file, compiled together.
 * Each returns the number of failed assertions in its suite. */
int run_json_tests(void);
int run_stream_tests(void);
int run_hex_tests(void);
int run_bpf_tests(void);
int run_beacon_tests(void);
int run_wpa_psk_tests(void);

int main(void)
{
    int failures = 0;

    printf("==============================================\n");
    printf("  pwn4cd daemon unit tests\n");
    printf("==============================================\n\n");

    failures += run_json_tests();
    printf("\n");
    failures += run_stream_tests();
    printf("\n");
    failures += run_hex_tests();
    printf("\n");
    failures += run_bpf_tests();
    printf("\n");
    failures += run_beacon_tests();
    printf("\n");
    failures += run_wpa_psk_tests();

    printf("\n==============================================\n");
    if (failures > 0) {
        printf("  FAILED: %d assertion(s)\n", failures);
    } else {
        printf("  All test suites completed.\n");
    }
    printf("==============================================\n");

    /* Propagate failures to the CI shell so regressions fail the build. */
    return failures > 0 ? 1 : 0;
}
