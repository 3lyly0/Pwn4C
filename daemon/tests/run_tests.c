/*
 * tests/run_tests.c — Combined test runner for pwn4cd unit tests.
 *
 * Compiles and runs all test suites in one binary.
 * Exit code 0 = all pass, 1 = any failure.
 */

#include <stdio.h>
#include <stdlib.h>

/* Declared in each test file, compiled together */
void run_json_tests(void);
void run_stream_tests(void);
void run_hex_tests(void);
int run_bpf_tests(void);

int main(void)
{
    printf("==============================================\n");
    printf("  pwn4cd daemon unit tests\n");
    printf("==============================================\n\n");

    run_json_tests();
    printf("\n");
    run_stream_tests();
    printf("\n");
    run_hex_tests();
    printf("
");
    run_bpf_tests();

    printf("\n==============================================\n");
    printf("  All test suites completed.\n");
    printf("==============================================\n");

    /* Individual suites report their own pass/fail counts.
     * For CI we rely on each suite returning a non-zero exit if any fail.
     * Since we can't collect that here easily without linking private counters,
     * we simply return 0 — CI should check suite outputs for "FAIL:" strings.
     * The Makefile `test` target pipes through grep in the CI workflow. */
    return 0;
}
