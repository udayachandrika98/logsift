/* A tiny C test harness.
 *
 * Test cases self-register through constructor attributes, and the runner
 * reports every failure rather than aborting on the first one.
 */

#ifndef CHECK_H
#define CHECK_H

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define CHECK_MAX_TESTS 128

typedef struct {
    const char *name;
    void (*body)(void);
} check_case_t;

static check_case_t check_cases[CHECK_MAX_TESTS];
static int check_case_count = 0;
static int check_current_failures = 0;
static char check_failure_text[512];

static inline void check_register(const char *name, void (*body)(void)) {
    if (check_case_count < CHECK_MAX_TESTS) {
        check_cases[check_case_count].name = name;
        check_cases[check_case_count].body = body;
        check_case_count++;
    }
}

static inline void check_fail(const char *file, int line, const char *message) {
    check_current_failures++;
    if (check_current_failures == 1) {
        snprintf(check_failure_text, sizeof(check_failure_text), "%s:%d  %s", file, line,
                 message);
    }
}

static inline int check_run_all(void) {
    int passed = 0, failed = 0;
    char failures[CHECK_MAX_TESTS][640];

    for (int i = 0; i < check_case_count; i++) {
        check_current_failures = 0;
        check_failure_text[0] = '\0';
        check_cases[i].body();
        if (check_current_failures == 0) {
            passed++;
            fputc('.', stdout);
        } else {
            snprintf(failures[failed], sizeof(failures[0]), "%s\n    %s",
                     check_cases[i].name, check_failure_text);
            failed++;
            fputc('F', stdout);
        }
        fflush(stdout);
    }

    printf("\n\n");
    for (int i = 0; i < failed; i++) printf("FAILED  %s\n\n", failures[i]);
    printf("%d passed", passed);
    if (failed) printf(", %d failed", failed);
    printf(" (%d tests)\n", check_case_count);
    return failed ? 1 : 0;
}

#define TEST(name)                                                    \
    static void name(void);                                           \
    __attribute__((constructor)) static void register_##name(void) {  \
        check_register(#name, name);                                  \
    }                                                                 \
    static void name(void)

#define CHECK(condition)                                                  \
    do {                                                                   \
        if (!(condition)) check_fail(__FILE__, __LINE__, "CHECK failed: " #condition); \
    } while (0)

#define CHECK_FALSE(condition) CHECK(!(condition))

#define CHECK_EQ(a, b)                                                     \
    do {                                                                    \
        if ((long long)(a) != (long long)(b)) {                             \
            char buffer[256];                                               \
            snprintf(buffer, sizeof(buffer), "expected %s == %s (got %lld vs %lld)", \
                     #a, #b, (long long)(a), (long long)(b));               \
            check_fail(__FILE__, __LINE__, buffer);                         \
        }                                                                   \
    } while (0)

#define CHECK_STR(a, b)                                                    \
    do {                                                                    \
        const char *lhs = (a);                                              \
        const char *rhs = (b);                                              \
        if (!lhs || !rhs || strcmp(lhs, rhs) != 0) {                        \
            char buffer[384];                                               \
            snprintf(buffer, sizeof(buffer), "expected %s == \"%s\" (got \"%s\")", \
                     #a, rhs ? rhs : "(null)", lhs ? lhs : "(null)");       \
            check_fail(__FILE__, __LINE__, buffer);                         \
        }                                                                   \
    } while (0)

#endif /* CHECK_H */
